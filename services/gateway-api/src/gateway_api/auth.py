"""Control Plane Credential authentication and Team Model Alias authorization."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import jwt
import yaml
from fastapi import Request, status
from jwt import PyJWK, PyJWKClient, PyJWKClientError, PyJWKSet, PyJWKSetError, PyJWTError
from pydantic import BaseModel, ConfigDict, Field

from gateway_api.config import ControlPlaneSettings
from platform_common import ActorContext, LoadedPolicyBundle, PolicyBundle

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_API_KEY_PREFIX = "sk-gw-"
_REQUIRED_JWT_CLAIMS = ["exp", "iss", "aud"]
_MIN_HS256_SECRET_BYTES = 32


class ApiKeyRecord(BaseModel):
    """Non-secret Actor metadata stored under a SHA-256 API key hash."""

    model_config = ConfigDict(frozen=True)

    actor_id: str = Field(min_length=1)
    team: str = Field(min_length=1)
    role: str = Field(min_length=1)
    revoked: bool = False


class GatewayAuthError(Exception):
    """Structured authentication or authorization failure converted to OpenAI JSON."""

    def __init__(
        self,
        *,
        status_code: int,
        message: str,
        error_type: str,
        code: str,
        param: str | None = None,
        denial_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.error_type = error_type
        self.code = code
        self.param = param
        self.denial_reason = denial_reason


def _validate_sha256_digest(raw_digest: object) -> str:
    if not isinstance(raw_digest, str):
        raise ValueError("API key store entry keys must be 64-character SHA-256 hex strings")
    normalized = raw_digest.strip().lower()
    if normalized.startswith(_API_KEY_PREFIX) or not _SHA256_HEX_RE.fullmatch(normalized):
        raise ValueError(
            "API key store entries must be keyed by 64-character SHA-256 hex digests, "
            "never plaintext sk-gw- credentials"
        )
    return normalized


def _parse_api_key_mapping(raw_store: object) -> dict[str, ApiKeyRecord]:
    if raw_store is None:
        return {}
    if not isinstance(raw_store, dict):
        raise ValueError("API key store must be a YAML/JSON mapping")

    entries = raw_store.get("api_keys", raw_store)
    records: dict[str, ApiKeyRecord] = {}

    if isinstance(entries, dict):
        for digest_key, entry_payload in entries.items():
            digest = _validate_sha256_digest(digest_key)
            records[digest] = ApiKeyRecord.model_validate(entry_payload)
        return records

    if isinstance(entries, list):
        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("API key store list items must be mappings")
            item_copy = dict(item)
            raw_digest = item_copy.pop("key_sha256", item_copy.pop("sha256", None))
            digest = _validate_sha256_digest(raw_digest)
            records[digest] = ApiKeyRecord.model_validate(item_copy)
        return records

    raise ValueError("API key store 'api_keys' must be a mapping or list")


def _load_api_key_store(settings: ControlPlaneSettings) -> dict[str, ApiKeyRecord]:
    store: dict[str, ApiKeyRecord] = {}

    if settings.api_keys_path is not None:
        key_path = Path(settings.api_keys_path)
        raw_text = key_path.read_text(encoding="utf-8")
        parsed_file = yaml.safe_load(raw_text)
        store.update(_parse_api_key_mapping(parsed_file))

    if settings.api_keys_json:
        parsed_json = json.loads(settings.api_keys_json)
        store.update(_parse_api_key_mapping(parsed_json))

    if settings.api_keys is not None:
        store.update(_parse_api_key_mapping(settings.api_keys))

    return store


def _load_static_jwk_set(settings: ControlPlaneSettings) -> PyJWKSet | None:
    combined_keys: list[dict[str, Any]] = []

    if settings.jwt_jwks_json:
        try:
            parsed = json.loads(settings.jwt_jwks_json)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid GATEWAY_JWT_JWKS_JSON") from exc
        if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
            raise ValueError("GATEWAY_JWT_JWKS_JSON must contain a 'keys' list")
        combined_keys.extend(parsed["keys"])

    if settings.jwt_jwks is not None:
        keys = settings.jwt_jwks.get("keys")
        if not isinstance(keys, list):
            raise ValueError("jwt_jwks must contain a 'keys' list")
        combined_keys.extend(keys)

    if not combined_keys:
        if settings.jwt_jwks_json or settings.jwt_jwks is not None:
            raise ValueError("Configured static JWKS contains no keys")
        return None

    try:
        return PyJWKSet.from_dict({"keys": combined_keys})
    except PyJWKSetError as exc:
        raise ValueError(f"Invalid static JWKS configuration: {exc}") from exc


def _extract_required_claim(claims: dict[str, Any], *names: str) -> str:
    for name in names:
        value = claims.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise GatewayAuthError(
        status_code=status.HTTP_401_UNAUTHORIZED,
        message="JWT credential is missing required Actor claims",
        error_type="authentication_error",
        code="invalid_credential",
    )


def extract_bearer_credential(authorization_header: str | None) -> str:
    """Parse an Authorization: Bearer <credential> header without leaking Credential values."""
    if not authorization_header:
        raise GatewayAuthError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message="Missing Authorization Bearer credential",
            error_type="authentication_error",
            code="missing_credential",
        )
    parts = authorization_header.strip().split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise GatewayAuthError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message="Malformed Authorization Bearer credential",
            error_type="authentication_error",
            code="invalid_credential",
        )
    return parts[1]


class AuthVerifier:
    """Verifies incoming Bearer Credentials against hashed API keys and JWTs."""

    def __init__(self, settings: ControlPlaneSettings) -> None:
        self.settings = settings
        self._api_key_store = _load_api_key_store(settings)
        self._static_jwk_set = _load_static_jwk_set(settings)
        self._jwks_client = (
            PyJWKClient(
                settings.jwt_jwks_url,
                lifespan=settings.jwt_jwks_cache_ttl_seconds,
            )
            if settings.jwt_jwks_url
            else None
        )
        self._hs256_secret = self._validate_hs256_secret(settings)

    @staticmethod
    def _validate_hs256_secret(settings: ControlPlaneSettings) -> str | None:
        if not settings.jwt_hs256_enabled or not settings.jwt_hs256_secret:
            return None
        if len(settings.jwt_hs256_secret.encode("utf-8")) < _MIN_HS256_SECRET_BYTES:
            raise ValueError(
                f"GATEWAY_JWT_HS256_SECRET must be at least {_MIN_HS256_SECRET_BYTES} bytes"
            )
        return settings.jwt_hs256_secret

    def _verify_api_key(self, plaintext_key: str) -> ActorContext:
        digest = hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()
        record = self._api_key_store.get(digest)
        if record is None or record.revoked:
            raise GatewayAuthError(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Invalid or revoked API key credential",
                error_type="authentication_error",
                code="invalid_credential",
            )
        return ActorContext(
            actor_id=record.actor_id,
            team=record.team,
            role=record.role,
            auth_method="api_key",
        )

    def _lookup_static_jwk(self, kid: object) -> PyJWK | None:
        if self._static_jwk_set is None or not isinstance(kid, str) or not kid:
            return None
        try:
            jwk = self._static_jwk_set[kid]
        except KeyError:
            return None
        if jwk.public_key_use not in (None, "sig"):
            return None
        return jwk

    async def _resolve_rs256_key(self, token: str, header: dict[str, Any]) -> PyJWK:
        static_key = self._lookup_static_jwk(header.get("kid"))
        if static_key is not None:
            return static_key

        if self._jwks_client is not None:
            try:
                return await asyncio.to_thread(
                    self._jwks_client.get_signing_key_from_jwt,
                    token,
                )
            except (PyJWKClientError, PyJWTError) as exc:
                raise GatewayAuthError(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    message="Unable to resolve JWT signing key",
                    error_type="authentication_error",
                    code="invalid_credential",
                ) from exc

        raise GatewayAuthError(
            status_code=status.HTTP_401_UNAUTHORIZED,
            message="Invalid JWT signing key",
            error_type="authentication_error",
            code="invalid_credential",
        )

    def _decode_jwt(self, token: str, key: Any, algorithm: str) -> dict[str, Any]:
        try:
            return jwt.decode(
                token,
                key,
                algorithms=[algorithm],
                issuer=self.settings.jwt_issuer,
                audience=self.settings.jwt_audience,
                leeway=self.settings.jwt_leeway_seconds,
                options={"require": _REQUIRED_JWT_CLAIMS},
            )
        except jwt.ExpiredSignatureError as exc:
            raise GatewayAuthError(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="JWT credential has expired",
                error_type="authentication_error",
                code="expired_credential",
            ) from exc
        except PyJWTError as exc:
            raise GatewayAuthError(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Invalid JWT credential",
                error_type="authentication_error",
                code="invalid_credential",
            ) from exc

    async def _verify_jwt(self, token: str) -> ActorContext:
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise GatewayAuthError(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Malformed JWT credential",
                error_type="authentication_error",
                code="invalid_credential",
            ) from exc

        alg = header.get("alg")
        if alg == "RS256":
            signing_key = await self._resolve_rs256_key(token, header)
            claims = self._decode_jwt(token, signing_key.key, "RS256")
        elif alg == "HS256" and self._hs256_secret is not None:
            claims = self._decode_jwt(token, self._hs256_secret, "HS256")
        else:
            raise GatewayAuthError(
                status_code=status.HTTP_401_UNAUTHORIZED,
                message="Unsupported or disabled JWT signing algorithm",
                error_type="authentication_error",
                code="invalid_credential",
            )

        actor_id = _extract_required_claim(claims, "sub", "actor_id")
        team = _extract_required_claim(claims, "team")
        role = _extract_required_claim(claims, "role")
        return ActorContext(
            actor_id=actor_id,
            team=team,
            role=role,
            auth_method="jwt",
        )

    async def verify_credential(self, credential: str) -> ActorContext:
        """Authenticate a parsed Bearer Credential into an ActorContext."""
        if credential.startswith(_API_KEY_PREFIX):
            return self._verify_api_key(credential)
        return await self._verify_jwt(credential)


async def authenticate_request(request: Request) -> ActorContext:
    """Authenticate the request Credential and attach ActorContext to request.state.actor."""
    credential = extract_bearer_credential(request.headers.get("authorization"))
    verifier: AuthVerifier = request.app.state.auth_verifier
    actor = await verifier.verify_credential(credential)
    request.state.actor = actor
    return actor


def authorize_model_alias(
    request: Request,
    actor: ActorContext,
    requested_model: str,
    policy: PolicyBundle,
) -> str:
    """Authorize Team Model Alias access and return the effective (possibly remapped) alias."""
    request.state.requested_model = requested_model
    team_policy = policy.teams.get(actor.team)
    if team_policy is None:
        raise GatewayAuthError(
            status_code=status.HTTP_403_FORBIDDEN,
            message=f"Team '{actor.team}' is not authorized in the Policy Bundle",
            error_type="permission_error",
            code="team_not_allowed",
            denial_reason="team_not_allowed",
        )

    if requested_model not in team_policy.allowed_model_aliases:
        raise GatewayAuthError(
            status_code=status.HTTP_403_FORBIDDEN,
            message=f"Model Alias '{requested_model}' is not allowed for Team '{actor.team}'",
            error_type="permission_error",
            code="model_not_allowed",
            param="model",
            denial_reason="model_not_allowed",
        )

    effective_model = team_policy.model_alias_remapping.get(requested_model, requested_model)
    request.state.effective_model = effective_model
    return effective_model


async def authenticate_and_authorize(request: Request, requested_model: str) -> str:
    """Authenticate request Credential, enforce Team Model Alias RBAC, and resolve remapping."""
    actor = await authenticate_request(request)
    loaded_policy: LoadedPolicyBundle = request.app.state.policy_bundle
    return authorize_model_alias(request, actor, requested_model, loaded_policy.bundle)
