"""Offline deterministic RSA keypair, JWKS, JWT, and sk-gw- API key generator for local/CI tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

DEFAULT_SEED = "ai-enablement-gateway-test-seed"
DEFAULT_KEY_ID = "test-rs256-key-1"
DEFAULT_ISSUER = "https://auth.ai-gateway.local"
DEFAULT_AUDIENCE = "ai-enablement-gateway"
DEFAULT_HS256_SECRET = "dev-only-hs256-signing-secret-minimum-32-bytes"
MIN_HS256_SECRET_BYTES = 32

_RSA_EXPONENT = 65537
_RSA_KEY_SIZE = 2048
_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53)
_MILLER_RABIN_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


@dataclass(frozen=True)
class TestRSAKeypair:
    """Generated RSA keypair and matching JWKS document for offline RS256 verification."""

    kid: str
    private_pem: str
    public_pem: str
    jwk: dict[str, Any]
    jwks: dict[str, list[dict[str, Any]]]


@dataclass(frozen=True)
class GeneratedApiKey:
    """Generated sk-gw- scoped API key Credential alongside its SHA-256 hash store record."""

    plaintext_key: str
    sha256: str
    actor_id: str
    team: str
    role: str
    revoked: bool = False

    def to_store_entry(self) -> dict[str, Any]:
        """Serialize the non-secret Actor metadata keyed by SHA-256 digest."""
        return {
            "actor_id": self.actor_id,
            "team": self.team,
            "role": self.role,
            "revoked": self.revoked,
        }


def _is_probable_prime(candidate: int) -> bool:
    if any(candidate % prime == 0 for prime in _SMALL_PRIMES):
        return False
    d = candidate - 1
    shift = 0
    while d % 2 == 0:
        d //= 2
        shift += 1
    for base in _MILLER_RABIN_BASES:
        if base >= candidate:
            continue
        x = pow(base, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(shift - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _deterministic_prime(rng: random.Random, bits: int) -> int:
    top_bits = 0b11 << (bits - 2)
    while True:
        candidate = rng.getrandbits(bits) | top_bits | 1
        if (candidate - 1) % _RSA_EXPONENT == 0:
            continue
        if _is_probable_prime(candidate):
            return candidate


@lru_cache(maxsize=32)
def _build_deterministic_rsa_keypair(seed: str, kid: str) -> TestRSAKeypair:
    seed_int = int.from_bytes(hashlib.sha256(seed.encode("utf-8")).digest(), "big")
    rng = random.Random(seed_int)
    half_bits = _RSA_KEY_SIZE // 2
    p = _deterministic_prime(rng, half_bits)
    q = _deterministic_prime(rng, half_bits)
    while q == p or math.gcd(_RSA_EXPONENT, (p - 1) * (q - 1)) != 1:
        q = _deterministic_prime(rng, half_bits)
    if p < q:
        p, q = q, p
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(_RSA_EXPONENT, -1, phi)
    private_key = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e=_RSA_EXPONENT, n=n),
    ).private_key()
    return _serialize_rsa_keypair(private_key, kid)


def _serialize_rsa_keypair(private_key: rsa.RSAPrivateKey, kid: str) -> TestRSAKeypair:
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    jwk_dict: dict[str, Any] = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk_dict.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return TestRSAKeypair(
        kid=kid,
        private_pem=private_pem,
        public_pem=public_pem,
        jwk=jwk_dict,
        jwks={"keys": [jwk_dict]},
    )


def generate_rsa_keypair(
    seed: str | None = DEFAULT_SEED,
    kid: str = DEFAULT_KEY_ID,
) -> TestRSAKeypair:
    """Generate an RSA-2048 keypair and JWKS, deterministically when ``seed`` is provided."""
    if seed is not None:
        return _build_deterministic_rsa_keypair(seed, kid)
    private_key = rsa.generate_private_key(
        public_exponent=_RSA_EXPONENT,
        key_size=_RSA_KEY_SIZE,
    )
    return _serialize_rsa_keypair(private_key, kid)


def _build_jwt_claims(
    *,
    actor_id: str,
    team: str,
    role: str,
    issuer: str,
    audience: str,
    expires_in_seconds: int,
    issued_at: int | None,
    extra_claims: dict[str, Any] | None,
    omit_claims: tuple[str, ...],
) -> dict[str, Any]:
    now = int(time.time()) if issued_at is None else issued_at
    claims: dict[str, Any] = {
        "sub": actor_id,
        "team": team,
        "role": role,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    if extra_claims:
        claims.update(extra_claims)
    for claim_name in omit_claims:
        claims.pop(claim_name, None)
    return claims


def mint_rs256_jwt(
    *,
    private_pem: str,
    kid: str = DEFAULT_KEY_ID,
    actor_id: str = "dev-alice",
    team: str = "platform-eng",
    role: str = "developer",
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
    expires_in_seconds: int = 3600,
    issued_at: int | None = None,
    extra_claims: dict[str, Any] | None = None,
    omit_claims: tuple[str, ...] = (),
) -> str:
    """Sign an RS256 JWT Credential for offline/local Control Plane verification."""
    claims = _build_jwt_claims(
        actor_id=actor_id,
        team=team,
        role=role,
        issuer=issuer,
        audience=audience,
        expires_in_seconds=expires_in_seconds,
        issued_at=issued_at,
        extra_claims=extra_claims,
        omit_claims=omit_claims,
    )
    headers = {"kid": kid} if kid else None
    return jwt.encode(claims, private_pem, algorithm="RS256", headers=headers)


def mint_hs256_jwt(
    *,
    secret: str = DEFAULT_HS256_SECRET,
    actor_id: str = "dev-alice",
    team: str = "platform-eng",
    role: str = "developer",
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
    expires_in_seconds: int = 3600,
    issued_at: int | None = None,
    extra_claims: dict[str, Any] | None = None,
    omit_claims: tuple[str, ...] = (),
) -> str:
    """Sign an HS256 JWT Credential using a >=32-byte test signing key."""
    if len(secret.encode("utf-8")) < MIN_HS256_SECRET_BYTES:
        raise ValueError(f"HS256 test secret must be at least {MIN_HS256_SECRET_BYTES} bytes long")
    claims = _build_jwt_claims(
        actor_id=actor_id,
        team=team,
        role=role,
        issuer=issuer,
        audience=audience,
        expires_in_seconds=expires_in_seconds,
        issued_at=issued_at,
        extra_claims=extra_claims,
        omit_claims=omit_claims,
    )
    return jwt.encode(claims, secret, algorithm="HS256")


def hash_api_key(plaintext_key: str) -> str:
    """Compute the canonical lowercase SHA-256 hex digest of an sk-gw- API key Credential."""
    return hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()


def generate_scoped_api_key(
    *,
    actor_id: str = "ci-bot-platform",
    team: str = "platform-eng",
    role: str = "developer",
    seed: str | None = DEFAULT_SEED,
    label: str = "default",
    revoked: bool = False,
    plaintext_key: str | None = None,
) -> GeneratedApiKey:
    """Create an sk-gw- scoped API key Credential and its SHA-256 hash store record."""
    if plaintext_key is None:
        if seed is not None:
            digest = hashlib.sha256(
                f"{seed}:{actor_id}:{team}:{role}:{label}".encode()
            ).hexdigest()[:24]
        else:
            digest = secrets.token_hex(12)
        resolved_key = f"sk-gw-{team}-{digest}"
    else:
        resolved_key = plaintext_key

    if not resolved_key.startswith("sk-gw-"):
        raise ValueError("Scoped API key Credential must start with 'sk-gw-'")

    return GeneratedApiKey(
        plaintext_key=resolved_key,
        sha256=hash_api_key(resolved_key),
        actor_id=actor_id,
        team=team,
        role=role,
        revoked=revoked,
    )


DEFAULT_LOCAL_ACTORS: tuple[tuple[str, str, str], ...] = (
    ("local-platform-admin", "platform-eng", "admin"),
    ("local-product-dev", "product-eng", "developer"),
    ("local-ops-user", "ops-eng", "ops"),
)


def generate_litellm_master_key(*, seed: str | None = DEFAULT_SEED) -> str:
    """Create an internal Model Router master key for local/CI secret bootstrap."""
    if seed is not None:
        digest = hashlib.sha256(f"{seed}:litellm-master-key".encode()).hexdigest()[:24]
    else:
        digest = secrets.token_hex(12)
    return f"sk-litellm-{digest}"


def generate_internal_identity_secret(*, seed: str | None = DEFAULT_SEED) -> str:
    """Create a >=32-byte HS256 secret shared by Control Plane and MCP Runtime."""
    if seed is not None:
        return hashlib.sha256(f"{seed}:internal-identity-secret".encode()).hexdigest()
    return secrets.token_hex(32)


def write_local_credential_bundle(
    bundle_dir: Path,
    *,
    seed: str | None = DEFAULT_SEED,
    kid: str = DEFAULT_KEY_ID,
    issuer: str = DEFAULT_ISSUER,
    audience: str = DEFAULT_AUDIENCE,
    ttl_seconds: int = 3600,
    issued_at: int | None = None,
) -> dict[str, str]:
    """Write a complete local Credential bundle and Terraform tfvars into ``bundle_dir``."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    keypair = generate_rsa_keypair(seed=seed, kid=kid)
    litellm_master_key = generate_litellm_master_key(seed=seed)
    internal_identity_secret = generate_internal_identity_secret(seed=seed)

    api_keys_store: dict[str, dict[str, Any]] = {}
    teams_bundle: dict[str, dict[str, Any]] = {}
    for actor_id, team, role in DEFAULT_LOCAL_ACTORS:
        api_key = generate_scoped_api_key(
            actor_id=actor_id,
            team=team,
            role=role,
            seed=seed,
            label="local-bundle",
        )
        api_keys_store[api_key.sha256] = api_key.to_store_entry()
        rs256_jwt = mint_rs256_jwt(
            private_pem=keypair.private_pem,
            kid=kid,
            actor_id=actor_id,
            team=team,
            role=role,
            issuer=issuer,
            audience=audience,
            expires_in_seconds=ttl_seconds,
            issued_at=issued_at,
        )
        teams_bundle[team] = {
            "actor_id": actor_id,
            "team": team,
            "role": role,
            "api_key": api_key.plaintext_key,
            "api_key_sha256": api_key.sha256,
            "rs256_jwt": rs256_jwt,
        }

    api_keys_doc = {"api_keys": api_keys_store}
    api_keys_json = json.dumps(api_keys_doc, indent=2, sort_keys=True) + "\n"
    jwks_json = json.dumps(keypair.jwks, indent=2, sort_keys=True) + "\n"

    credentials_doc = {
        "kid": keypair.kid,
        "issuer": issuer,
        "audience": audience,
        "jwks": keypair.jwks,
        "private_pem": keypair.private_pem,
        "public_pem": keypair.public_pem,
        "litellm_master_key": litellm_master_key,
        "internal_identity_secret": internal_identity_secret,
        "teams": teams_bundle,
    }
    tfvars_doc = {
        "gateway_api_keys_json": json.dumps(api_keys_doc, separators=(",", ":"), sort_keys=True),
        "gateway_jwks_json": json.dumps(keypair.jwks, separators=(",", ":"), sort_keys=True),
        "litellm_master_key": litellm_master_key,
        "internal_identity_secret": internal_identity_secret,
    }

    jwks_path = bundle_dir / "jwks.json"
    private_path = bundle_dir / "private.pem"
    public_path = bundle_dir / "public.pem"
    api_keys_path = bundle_dir / "api-keys.json"
    credentials_path = bundle_dir / "credentials.json"
    tfvars_path = bundle_dir / "local.tfvars.json"

    jwks_path.write_text(jwks_json, encoding="utf-8")
    private_path.write_text(keypair.private_pem, encoding="utf-8")
    public_path.write_text(keypair.public_pem, encoding="utf-8")
    api_keys_path.write_text(api_keys_json, encoding="utf-8")
    credentials_path.write_text(
        json.dumps(credentials_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    tfvars_path.write_text(
        json.dumps(tfvars_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    for sensitive_path in (private_path, credentials_path, tfvars_path):
        sensitive_path.chmod(0o600)

    return {
        "bundle_dir": str(bundle_dir),
        "jwks_path": str(jwks_path),
        "private_pem_path": str(private_path),
        "public_pem_path": str(public_path),
        "api_keys_path": str(api_keys_path),
        "credentials_path": str(credentials_path),
        "tfvars_path": str(tfvars_path),
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate deterministic offline test RSA keypair, JWKS, JWTs, "
            "and sk-gw- API key hashes."
        ),
    )
    parser.add_argument("--seed", default=DEFAULT_SEED, help="Deterministic generation seed.")
    parser.add_argument("--random", action="store_true", help="Use random entropy instead of seed.")
    parser.add_argument("--kid", default=DEFAULT_KEY_ID, help="JWKS key ID (kid).")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help="JWT iss claim.")
    parser.add_argument("--audience", default=DEFAULT_AUDIENCE, help="JWT aud claim.")
    parser.add_argument(
        "--actor-id",
        default="dev-alice",
        help="Actor ID for generated credentials.",
    )
    parser.add_argument("--team", default="platform-eng", help="Team for generated credentials.")
    parser.add_argument("--role", default="developer", help="Role for generated credentials.")
    parser.add_argument("--ttl-seconds", type=int, default=3600, help="JWT expiration TTL.")
    parser.add_argument("--issued-at", type=int, default=None, help="Fixed iat epoch timestamp.")
    parser.add_argument(
        "--hs256-secret",
        default=DEFAULT_HS256_SECRET,
        help="HS256 signing secret (>=32 bytes).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional directory to write jwks.json, private.pem, public.pem, and api-keys.yaml.",
    )
    parser.add_argument(
        "--write-bundle",
        type=Path,
        default=None,
        help=(
            "Write a multi-Team local Credential bundle (credentials.json, api-keys.json, "
            "jwks.json, private.pem, public.pem, and local.tfvars.json)."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for generating offline test keys and Credentials."""
    args = _parse_args(argv)
    seed = None if args.random else args.seed

    if args.write_bundle is not None:
        summary = write_local_credential_bundle(
            args.write_bundle,
            seed=seed,
            kid=args.kid,
            issuer=args.issuer,
            audience=args.audience,
            ttl_seconds=args.ttl_seconds,
            issued_at=args.issued_at,
        )
        print(
            json.dumps(
                {"teams": [team for _, team, _ in DEFAULT_LOCAL_ACTORS], **summary},
                indent=2,
            )
        )
        return 0

    keypair = generate_rsa_keypair(seed=seed, kid=args.kid)
    rs256_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=args.kid,
        actor_id=args.actor_id,
        team=args.team,
        role=args.role,
        issuer=args.issuer,
        audience=args.audience,
        expires_in_seconds=args.ttl_seconds,
        issued_at=args.issued_at,
    )
    hs256_jwt = mint_hs256_jwt(
        secret=args.hs256_secret,
        actor_id=args.actor_id,
        team=args.team,
        role=args.role,
        issuer=args.issuer,
        audience=args.audience,
        expires_in_seconds=args.ttl_seconds,
        issued_at=args.issued_at,
    )
    api_key = generate_scoped_api_key(
        actor_id=args.actor_id,
        team=args.team,
        role=args.role,
        seed=seed,
    )
    api_keys_store = {"api_keys": {api_key.sha256: api_key.to_store_entry()}}

    output: dict[str, Any] = {
        "kid": keypair.kid,
        "issuer": args.issuer,
        "audience": args.audience,
        "jwks": keypair.jwks,
        "rs256_jwt": rs256_jwt,
        "hs256_jwt": hs256_jwt,
        "api_key": api_key.plaintext_key,
        "api_key_sha256": api_key.sha256,
        "api_keys_store": api_keys_store,
    }

    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        jwks_path = args.output_dir / "jwks.json"
        private_path = args.output_dir / "private.pem"
        public_path = args.output_dir / "public.pem"
        api_keys_path = args.output_dir / "api-keys.yaml"

        jwks_path.write_text(json.dumps(keypair.jwks, indent=2) + "\n", encoding="utf-8")
        private_path.write_text(keypair.private_pem, encoding="utf-8")
        public_path.write_text(keypair.public_pem, encoding="utf-8")
        api_keys_path.write_text(yaml.safe_dump(api_keys_store, sort_keys=True), encoding="utf-8")

        output["jwks_path"] = str(jwks_path)
        output["private_pem_path"] = str(private_path)
        output["public_pem_path"] = str(public_path)
        output["api_keys_path"] = str(api_keys_path)

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
