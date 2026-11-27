"""Short-lived signed internal identity assertion helpers for Control Plane -> MCP Runtime."""

from __future__ import annotations

import time
import uuid
from typing import Any, Literal

import jwt
from jwt import PyJWTError
from pydantic import BaseModel, ConfigDict

from platform_common.models import ActorContext

INTERNAL_IDENTITY_HEADER = "x-internal-actor-assertion"
INTERNAL_IDENTITY_ISSUER = "ai-gateway-control-plane"
INTERNAL_IDENTITY_AUDIENCE = "ai-gateway-mcp-runtime"
MIN_INTERNAL_IDENTITY_SECRET_BYTES = 32

_REQUIRED_CLAIMS = [
    "exp",
    "iat",
    "iss",
    "aud",
    "sub",
    "actor_id",
    "team",
    "role",
    "run_id",
    "trace_id",
]


class InternalIdentityAssertion(BaseModel):
    """Verified internal Actor identity and Run context propagated to MCP Runtime."""

    model_config = ConfigDict(frozen=True)

    actor_id: str
    team: str
    role: str
    run_id: str
    trace_id: str
    iat: int
    exp: int
    jti: str = ""


class InternalIdentityError(Exception):
    """Structured error raised when an internal actor assertion is missing, expired, or invalid."""

    def __init__(
        self,
        code: Literal["missing_assertion", "expired_assertion", "invalid_assertion"],
        message: str,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def validate_internal_identity_secret(secret: str | None) -> str:
    """Validate that the internal identity signing secret is configured and >= 32 bytes."""
    if (
        not isinstance(secret, str)
        or len(secret.encode("utf-8")) < MIN_INTERNAL_IDENTITY_SECRET_BYTES
    ):
        raise ValueError(
            "Internal identity signing secret must be at least "
            f"{MIN_INTERNAL_IDENTITY_SECRET_BYTES} bytes"
        )
    return secret


def _require_non_empty_claim(claims: dict[str, Any], key: str) -> str:
    value = claims.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InternalIdentityError(
            code="invalid_assertion",
            message=f"Internal actor assertion claim '{key}' must be a non-empty string",
        )
    return value.strip()


def _require_int_claim(claims: dict[str, Any], key: str) -> int:
    value = claims.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise InternalIdentityError(
            code="invalid_assertion",
            message=f"Internal actor assertion claim '{key}' must be an integer",
        )
    return value


def sign_internal_identity_assertion(
    *,
    actor: ActorContext,
    run_id: str,
    trace_id: str,
    secret: str,
    ttl_seconds: int = 30,
    now: int | None = None,
) -> str:
    """Mint a short-lived HS256 JWT asserting verified Actor, Run, and trace identity."""
    validated_secret = validate_internal_identity_secret(secret)
    if ttl_seconds < 1:
        raise ValueError("ttl_seconds must be at least 1")

    actor_id = actor.actor_id.strip()
    team = actor.team.strip()
    role = actor.role.strip()
    clean_run_id = run_id.strip()
    clean_trace_id = trace_id.strip()
    if not actor_id or not team or not role or not clean_run_id or not clean_trace_id:
        raise ValueError(
            "actor_id, team, role, run_id, and trace_id must be non-empty when signing assertions"
        )

    issued_at = int(time.time()) if now is None else int(now)
    claims: dict[str, Any] = {
        "iss": INTERNAL_IDENTITY_ISSUER,
        "aud": INTERNAL_IDENTITY_AUDIENCE,
        "sub": actor_id,
        "actor_id": actor_id,
        "team": team,
        "role": role,
        "run_id": clean_run_id,
        "trace_id": clean_trace_id,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, validated_secret, algorithm="HS256")


def verify_internal_identity_assertion(
    token: str | None,
    *,
    secret: str,
    leeway_seconds: int = 0,
) -> InternalIdentityAssertion:
    """Cryptographically verify an HS256 internal actor assertion issued by the Control Plane."""
    validated_secret = validate_internal_identity_secret(secret)
    if token is None or not isinstance(token, str) or not token.strip():
        raise InternalIdentityError(
            code="missing_assertion",
            message="Missing internal actor assertion",
        )

    raw_token = token.strip()
    try:
        header = jwt.get_unverified_header(raw_token)
    except PyJWTError as exc:
        raise InternalIdentityError(
            code="invalid_assertion",
            message="Malformed internal actor assertion header",
        ) from exc

    if header.get("alg") != "HS256":
        raise InternalIdentityError(
            code="invalid_assertion",
            message="Unsupported internal actor assertion signing algorithm",
        )

    try:
        claims = jwt.decode(
            raw_token,
            validated_secret,
            algorithms=["HS256"],
            issuer=INTERNAL_IDENTITY_ISSUER,
            audience=INTERNAL_IDENTITY_AUDIENCE,
            leeway=leeway_seconds,
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.ExpiredSignatureError as exc:
        raise InternalIdentityError(
            code="expired_assertion",
            message="Internal actor assertion has expired",
        ) from exc
    except PyJWTError as exc:
        raise InternalIdentityError(
            code="invalid_assertion",
            message="Invalid internal actor assertion",
        ) from exc

    _require_non_empty_claim(claims, "sub")
    actor_id = _require_non_empty_claim(claims, "actor_id")
    team = _require_non_empty_claim(claims, "team")
    role = _require_non_empty_claim(claims, "role")
    run_id = _require_non_empty_claim(claims, "run_id")
    trace_id = _require_non_empty_claim(claims, "trace_id")
    iat = _require_int_claim(claims, "iat")
    exp = _require_int_claim(claims, "exp")

    raw_jti = claims.get("jti")
    jti = raw_jti.strip() if isinstance(raw_jti, str) else ""

    return InternalIdentityAssertion(
        actor_id=actor_id,
        team=team,
        role=role,
        run_id=run_id,
        trace_id=trace_id,
        iat=iat,
        exp=exp,
        jti=jti,
    )
