"""Offline Control Plane HTTP-seam tests for Credential authentication and Team RBAC."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import fakeredis
import httpx
import jwt
import pytest
import yaml

from gateway_api.app import create_app
from gateway_api.config import ControlPlaneSettings
from mock_llm.app import create_app as create_mock_provider_app
from mock_llm.config import MockProviderSettings
from scripts.generate_test_keys import (
    DEFAULT_AUDIENCE,
    DEFAULT_HS256_SECRET,
    DEFAULT_ISSUER,
    generate_rsa_keypair,
    generate_scoped_api_key,
    hash_api_key,
    mint_hs256_jwt,
    mint_rs256_jwt,
)

POLICY_BUNDLE_PATH = Path(__file__).resolve().parent.parent / "policies" / "policy-bundle.yaml"


class RecordingTransport(httpx.AsyncBaseTransport):
    """Wrap an ASGI transport to count requests forwarded to the Model Router."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self.inner = inner
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def _make_gateway_and_recorder(
    **settings_overrides: object,
) -> tuple[object, RecordingTransport]:
    mock_app = create_mock_provider_app(
        settings=MockProviderSettings(provider_name="mock-llm-primary", mock_mode_enabled=True)
    )
    recorder = RecordingTransport(httpx.ASGITransport(app=mock_app))
    settings_kwargs: dict[str, object] = {
        "policy_bundle_path": POLICY_BUNDLE_PATH,
        "model_router_base_url": "http://mock-provider",
    }
    settings_kwargs.update(settings_overrides)
    app = create_app(
        settings=ControlPlaneSettings(**settings_kwargs),  # type: ignore[arg-type]
        model_router_transport=recorder,
        redis_client=fakeredis.FakeAsyncRedis(decode_responses=True),
    )
    return app, recorder


def test_deterministic_test_credential_generator_produces_valid_rsa_hs256_and_api_keys(
    tmp_path: Path,
) -> None:
    kp_a = generate_rsa_keypair(seed="ci-seed-1", kid="kid-1")
    kp_b = generate_rsa_keypair(seed="ci-seed-1", kid="kid-1")
    kp_other = generate_rsa_keypair(seed="ci-seed-2", kid="kid-1")

    assert kp_a.private_pem == kp_b.private_pem
    assert kp_a.jwks == kp_b.jwks
    assert kp_a.jwks != kp_other.jwks
    assert kp_a.jwks["keys"][0]["kid"] == "kid-1"
    assert kp_a.jwks["keys"][0]["alg"] == "RS256"
    assert kp_a.jwks["keys"][0]["use"] == "sig"

    rs_tok_a = mint_rs256_jwt(
        private_pem=kp_a.private_pem,
        kid="kid-1",
        actor_id="alice",
        team="platform-eng",
        role="developer",
        issued_at=1_700_000_000,
        expires_in_seconds=3600,
    )
    rs_tok_b = mint_rs256_jwt(
        private_pem=kp_b.private_pem,
        kid="kid-1",
        actor_id="alice",
        team="platform-eng",
        role="developer",
        issued_at=1_700_000_000,
        expires_in_seconds=3600,
    )
    assert rs_tok_a == rs_tok_b
    header = jwt.get_unverified_header(rs_tok_a)
    assert header["alg"] == "RS256"
    assert header["kid"] == "kid-1"

    assert len(DEFAULT_HS256_SECRET.encode("utf-8")) >= 32
    hs_tok = mint_hs256_jwt(
        secret=DEFAULT_HS256_SECRET,
        actor_id="bob",
        team="product-eng",
        role="ops",
        issued_at=1_700_000_000,
        expires_in_seconds=3600,
    )
    decoded_hs = jwt.decode(
        hs_tok,
        DEFAULT_HS256_SECRET,
        algorithms=["HS256"],
        issuer=DEFAULT_ISSUER,
        audience=DEFAULT_AUDIENCE,
        options={"verify_exp": False},
    )
    assert decoded_hs["sub"] == "bob"
    assert decoded_hs["team"] == "product-eng"
    assert decoded_hs["role"] == "ops"

    api_key_a = generate_scoped_api_key(
        actor_id="ci-bot", team="platform-eng", role="developer", seed="ci-seed-1"
    )
    api_key_b = generate_scoped_api_key(
        actor_id="ci-bot", team="platform-eng", role="developer", seed="ci-seed-1"
    )
    assert api_key_a.plaintext_key == api_key_b.plaintext_key
    assert api_key_a.plaintext_key.startswith("sk-gw-")
    assert api_key_a.sha256 == hash_api_key(api_key_a.plaintext_key)
    assert len(api_key_a.sha256) == 64

    # CLI execution writes deterministic artifacts offline
    out_dir = tmp_path / "keys"
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/generate_test_keys.py",
            "--seed",
            "ci-seed-1",
            "--kid",
            "kid-1",
            "--actor-id",
            "alice",
            "--team",
            "platform-eng",
            "--role",
            "developer",
            "--issued-at",
            "1700000000",
            "--output-dir",
            str(out_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    cli_payload = json.loads(proc.stdout)
    assert cli_payload["rs256_jwt"] == rs_tok_a
    assert (out_dir / "jwks.json").exists()
    assert (out_dir / "api-keys.yaml").exists()


@pytest.mark.parametrize(
    "auth_headers",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer   "},
        {"Authorization": "Bearer token-part-1 token-part-2"},
    ],
)
async def test_missing_or_malformed_authorization_returns_401_without_upstream_call(
    auth_headers: dict[str, str],
) -> None:
    keypair = generate_rsa_keypair()
    app, recorder = _make_gateway_and_recorder(jwt_jwks=keypair.jwks)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        assert (await client.get("/healthz")).status_code == 200
        assert (await client.get("/readyz")).status_code == 200

        resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Should be rejected"}],
            },
            headers=auth_headers,
        )

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
    assert resp.headers["x-policy-version"].startswith("v1+")
    error = resp.json()["error"]
    assert error["type"] == "authentication_error"
    assert error["code"] in {"missing_credential", "invalid_credential"}
    assert len(recorder.requests) == 0


def _attach_state_capture(app: object) -> dict[str, object]:
    """Record request.state fields written by Control Plane auth/RBAC during HTTP calls."""
    captured: dict[str, object] = {}

    @app.middleware("http")  # type: ignore[attr-defined]
    async def capture_state(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        captured["actor"] = getattr(request.state, "actor", None)
        captured["requested_model"] = getattr(request.state, "requested_model", None)
        captured["effective_model"] = getattr(request.state, "effective_model", None)
        return response

    return captured


async def test_scoped_api_key_valid_resolves_actor_from_yaml_json_and_dict(
    tmp_path: Path,
) -> None:
    yaml_key = generate_scoped_api_key(
        actor_id="svc-deploy", team="ops-eng", role="ops", label="yaml"
    )
    json_key = generate_scoped_api_key(
        actor_id="svc-web", team="platform-eng", role="developer", label="json"
    )
    dict_key = generate_scoped_api_key(
        actor_id="svc-admin", team="platform-eng", role="admin", label="dict"
    )

    keys_file = tmp_path / "api-keys.yaml"
    keys_file.write_text(
        yaml.safe_dump({"api_keys": {yaml_key.sha256: yaml_key.to_store_entry()}}),
        encoding="utf-8",
    )

    app, recorder = _make_gateway_and_recorder(
        api_keys_path=keys_file,
        api_keys_json=json.dumps({json_key.sha256: json_key.to_store_entry()}),
        api_keys={dict_key.sha256: dict_key.to_store_entry()},
    )
    captured = _attach_state_capture(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        for generated in (yaml_key, json_key, dict_key):
            resp = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "chat-default",
                    "messages": [{"role": "user", "content": "Hello via API key"}],
                },
                headers={"Authorization": f"Bearer {generated.plaintext_key}"},
            )
            assert resp.status_code == 200
            actor = captured["actor"]
            assert actor is not None
            assert actor.actor_id == generated.actor_id  # type: ignore[attr-defined]
            assert actor.team == generated.team  # type: ignore[attr-defined]
            assert actor.role == generated.role  # type: ignore[attr-defined]
            assert actor.auth_method == "api_key"  # type: ignore[attr-defined]

    assert len(recorder.requests) == 3


async def test_unknown_or_revoked_scoped_api_key_returns_401_without_upstream_call() -> None:
    active_key = generate_scoped_api_key(
        actor_id="svc-active", team="platform-eng", role="developer", label="active"
    )
    revoked_key = generate_scoped_api_key(
        actor_id="svc-revoked",
        team="platform-eng",
        role="developer",
        label="revoked",
        revoked=True,
    )
    unknown_key = generate_scoped_api_key(
        actor_id="svc-unknown", team="platform-eng", role="developer", label="unknown"
    )

    app, recorder = _make_gateway_and_recorder(
        api_keys={
            active_key.sha256: active_key.to_store_entry(),
            revoked_key.sha256: revoked_key.to_store_entry(),
        }
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        revoked_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Revoked key"}],
            },
            headers={"Authorization": f"Bearer {revoked_key.plaintext_key}"},
        )
        unknown_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Unknown key"}],
            },
            headers={"Authorization": f"Bearer {unknown_key.plaintext_key}"},
        )
        # Presenting the SHA-256 hex digest itself instead of sk-gw- must not authenticate
        digest_as_bearer = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Digest presented directly"}],
            },
            headers={"Authorization": f"Bearer {active_key.sha256}"},
        )

    for resp in (revoked_resp, unknown_resp, digest_as_bearer):
        assert resp.status_code == 401
        assert resp.json()["error"]["type"] == "authentication_error"
        assert active_key.plaintext_key not in resp.text
        assert revoked_key.plaintext_key not in resp.text
    assert len(recorder.requests) == 0


def test_api_key_store_rejects_plaintext_sk_gw_keys_and_missing_file(tmp_path: Path) -> None:
    plaintext_key = generate_scoped_api_key(label="plaintext").plaintext_key
    with pytest.raises(ValueError, match="SHA-256"):
        _make_gateway_and_recorder(
            api_keys={
                plaintext_key: {
                    "actor_id": "bad",
                    "team": "platform-eng",
                    "role": "developer",
                }
            }
        )

    with pytest.raises(FileNotFoundError):
        _make_gateway_and_recorder(api_keys_path=tmp_path / "missing-api-keys.yaml")


def _start_jwks_server(jwks: dict[str, object]) -> tuple[ThreadingHTTPServer, str]:
    body = json.dumps(jwks).encode("utf-8")

    class _JwksHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/.well-known/jwks.json":
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _JwksHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/.well-known/jwks.json"


async def test_rs256_jwt_valid_via_static_jwks_and_jwks_url() -> None:
    keypair = generate_rsa_keypair(seed="rs256-valid")
    token = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="alice-eng",
        team="platform-eng",
        role="ops",
    )

    # Static JWKS JSON string
    app_static, recorder_static = _make_gateway_and_recorder(jwt_jwks_json=json.dumps(keypair.jwks))
    captured_static = _attach_state_capture(app_static)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_static),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        resp_static = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": [{"role": "user", "content": "Hi"}]},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert resp_static.status_code == 200
    assert captured_static["actor"].actor_id == "alice-eng"  # type: ignore[attr-defined]
    assert captured_static["actor"].team == "platform-eng"  # type: ignore[attr-defined]
    assert captured_static["actor"].role == "ops"  # type: ignore[attr-defined]
    assert captured_static["actor"].auth_method == "jwt"  # type: ignore[attr-defined]
    assert len(recorder_static.requests) == 1

    # Remote JWKS URL via PyJWKClient (offline local HTTP server)
    server, jwks_url = _start_jwks_server(keypair.jwks)
    try:
        app_url, recorder_url = _make_gateway_and_recorder(jwt_jwks_url=jwks_url)
        captured_url = _attach_state_capture(app_url)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_url),  # type: ignore[arg-type]
            base_url="http://control-plane",
        ) as client:
            resp_url = await client.post(
                "/v1/chat/completions",
                json={"model": "chat-default", "messages": [{"role": "user", "content": "Hi"}]},
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        server.shutdown()
        server.server_close()

    assert resp_url.status_code == 200
    assert captured_url["actor"].actor_id == "alice-eng"  # type: ignore[attr-defined]
    assert captured_url["actor"].auth_method == "jwt"  # type: ignore[attr-defined]
    assert len(recorder_url.requests) == 1


@pytest.mark.parametrize(
    "case",
    [
        "expired",
        "wrong_issuer",
        "wrong_audience",
        "missing_exp",
        "missing_iss",
        "missing_aud",
        "missing_sub",
        "missing_team",
        "missing_role",
        "wrong_signing_key",
        "unknown_kid",
        "malformed_jwt",
        "alg_none",
    ],
)
async def test_rs256_jwt_invalid_cases_return_401_without_upstream_call(case: str) -> None:
    trusted_kp = generate_rsa_keypair(seed="trusted-jwks", kid="trusted-kid")
    untrusted_kp = generate_rsa_keypair(seed="untrusted-jwks", kid="trusted-kid")

    if case == "expired":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            expires_in_seconds=-120,
        )
    elif case == "wrong_issuer":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            issuer="https://untrusted-idp.example.com",
        )
    elif case == "wrong_audience":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            audience="wrong-audience",
        )
    elif case == "missing_exp":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            omit_claims=("exp",),
        )
    elif case == "missing_iss":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            omit_claims=("iss",),
        )
    elif case == "missing_aud":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            omit_claims=("aud",),
        )
    elif case == "missing_sub":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            omit_claims=("sub",),
        )
    elif case == "missing_team":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            omit_claims=("team",),
        )
    elif case == "missing_role":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="trusted-kid",
            omit_claims=("role",),
        )
    elif case == "wrong_signing_key":
        token = mint_rs256_jwt(
            private_pem=untrusted_kp.private_pem,
            kid="trusted-kid",
        )
    elif case == "unknown_kid":
        token = mint_rs256_jwt(
            private_pem=trusted_kp.private_pem,
            kid="unknown-kid",
        )
    elif case == "malformed_jwt":
        token = "not-even-a-jwt"
    elif case == "alg_none":
        token = jwt.encode(
            {
                "sub": "alice",
                "team": "platform-eng",
                "role": "developer",
                "iss": DEFAULT_ISSUER,
                "aud": DEFAULT_AUDIENCE,
                "exp": 9_999_999_999,
            },
            key=None,  # type: ignore[arg-type]
            algorithm="none",
        )
    else:
        raise AssertionError(f"Unhandled case {case}")

    app, recorder = _make_gateway_and_recorder(jwt_jwks=trusted_kp.jwks)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": [{"role": "user", "content": "Reject"}]},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate") == "Bearer"
    assert resp.json()["error"]["type"] == "authentication_error"
    assert token not in resp.text
    assert len(recorder.requests) == 0


async def test_hs256_jwt_disabled_by_default_and_allowed_only_when_explicitly_enabled() -> None:
    hs_token = mint_hs256_jwt(
        secret=DEFAULT_HS256_SECRET,
        actor_id="dev-hs",
        team="platform-eng",
        role="developer",
    )

    # Disabled by default (even if secret is configured)
    app_disabled, recorder_disabled = _make_gateway_and_recorder(
        jwt_hs256_secret=DEFAULT_HS256_SECRET,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_disabled),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        denied_resp = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": [{"role": "user", "content": "Hi"}]},
            headers={"Authorization": f"Bearer {hs_token}"},
        )
    assert denied_resp.status_code == 401
    assert len(recorder_disabled.requests) == 0

    # Enabled explicitly
    app_enabled, recorder_enabled = _make_gateway_and_recorder(
        jwt_hs256_enabled=True,
        jwt_hs256_secret=DEFAULT_HS256_SECRET,
    )
    captured = _attach_state_capture(app_enabled)
    wrong_secret_token = mint_hs256_jwt(
        secret="wrong-hs256-signing-secret-minimum-32-bytes!",
        actor_id="dev-hs",
        team="platform-eng",
        role="developer",
    )
    expired_hs_token = mint_hs256_jwt(
        secret=DEFAULT_HS256_SECRET,
        actor_id="dev-hs",
        team="platform-eng",
        role="developer",
        expires_in_seconds=-60,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_enabled),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        ok_resp = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": [{"role": "user", "content": "Hi"}]},
            headers={"Authorization": f"Bearer {hs_token}"},
        )
        assert ok_resp.status_code == 200
        assert captured["actor"].actor_id == "dev-hs"  # type: ignore[attr-defined]
        assert captured["actor"].auth_method == "jwt"  # type: ignore[attr-defined]

        wrong_resp = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": [{"role": "user", "content": "Hi"}]},
            headers={"Authorization": f"Bearer {wrong_secret_token}"},
        )
        expired_resp = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": [{"role": "user", "content": "Hi"}]},
            headers={"Authorization": f"Bearer {expired_hs_token}"},
        )

    assert wrong_resp.status_code == 401
    assert expired_resp.status_code == 401
    assert len(recorder_enabled.requests) == 1


def test_hs256_enabled_with_short_secret_fails_fast() -> None:
    with pytest.raises(ValueError, match="32"):
        _make_gateway_and_recorder(
            jwt_hs256_enabled=True,
            jwt_hs256_secret="short-secret",
        )


async def test_team_model_alias_rbac_denies_with_403_before_upstream() -> None:
    keypair = generate_rsa_keypair(seed="rbac-403")
    product_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="prod-dev",
        team="product-eng",
        role="developer",
    )
    unknown_team_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="stranger",
        team="unknown-team",
        role="developer",
    )
    platform_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="plat-dev",
        team="platform-eng",
        role="developer",
    )

    app, recorder = _make_gateway_and_recorder(jwt_jwks=keypair.jwks)
    captured = _attach_state_capture(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        denied_model_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-premium",
                "messages": [{"role": "user", "content": "Request disallowed model"}],
            },
            headers={"Authorization": f"Bearer {product_jwt}"},
        )
        assert denied_model_resp.status_code == 403
        assert denied_model_resp.headers["x-policy-version"].startswith("v1+")
        assert denied_model_resp.json()["error"]["type"] == "permission_error"
        assert denied_model_resp.json()["error"]["code"] == "model_not_allowed"
        assert denied_model_resp.json()["error"]["param"] == "model"
        assert captured["actor"].team == "product-eng"  # type: ignore[attr-defined]
        assert captured["requested_model"] == "chat-premium"

        unknown_team_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Request from unknown team"}],
            },
            headers={"Authorization": f"Bearer {unknown_team_jwt}"},
        )
        assert unknown_team_resp.status_code == 403
        assert unknown_team_resp.json()["error"]["type"] == "permission_error"
        assert unknown_team_resp.json()["error"]["code"] == "team_not_allowed"
        assert len(recorder.requests) == 0

        allowed_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-premium",
                "messages": [{"role": "user", "content": "Allowed for platform-eng"}],
            },
            headers={"Authorization": f"Bearer {platform_jwt}"},
        )
        assert allowed_resp.status_code == 200
        assert allowed_resp.json()["model"] == "chat-premium"
        assert captured["requested_model"] == "chat-premium"
        assert captured["effective_model"] == "chat-premium"
        assert len(recorder.requests) == 1


async def test_per_team_model_alias_remapping_rewrites_model_before_forwarding(
    tmp_path: Path,
) -> None:
    bundle_data = yaml.safe_load(POLICY_BUNDLE_PATH.read_text(encoding="utf-8"))
    bundle_data["teams"]["product-eng"]["model_alias_remapping"] = {
        "chat-default": "chat-fast",
        "chat-premium": "chat-fast",  # Still disallowed because not in allowed_model_aliases
    }
    remapped_policy_path = tmp_path / "policy-bundle.yaml"
    remapped_policy_path.write_text(yaml.safe_dump(bundle_data), encoding="utf-8")

    keypair = generate_rsa_keypair(seed="remap-test")
    product_jwt = mint_rs256_jwt(
        private_pem=keypair.private_pem,
        kid=keypair.kid,
        actor_id="prod-remap-actor",
        team="product-eng",
        role="developer",
    )
    product_api_key = generate_scoped_api_key(
        actor_id="prod-remap-svc",
        team="product-eng",
        role="developer",
        seed="remap-test",
    )

    app, recorder = _make_gateway_and_recorder(
        policy_bundle_path=remapped_policy_path,
        jwt_jwks=keypair.jwks,
        api_keys={product_api_key.sha256: product_api_key.to_store_entry()},
    )
    captured = _attach_state_capture(app)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        # JSON request via JWT: chat-default -> chat-fast
        json_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Remap JSON request"}],
                "stream": False,
            },
            headers={"Authorization": f"Bearer {product_jwt}"},
        )
        assert json_resp.status_code == 200
        json_body = json_resp.json()
        assert json_body["model"] == "chat-fast"
        assert "[mock-llm-primary:chat-fast]" in json_body["choices"][0]["message"]["content"]
        assert captured["requested_model"] == "chat-default"
        assert captured["effective_model"] == "chat-fast"
        assert json.loads(recorder.requests[0].content)["model"] == "chat-fast"

        # JSON request via sk-gw- API key: chat-default -> chat-fast
        api_key_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Remap API key request"}],
                "stream": False,
            },
            headers={"Authorization": f"Bearer {product_api_key.plaintext_key}"},
        )
        assert api_key_resp.status_code == 200
        assert api_key_resp.json()["model"] == "chat-fast"
        assert captured["actor"].auth_method == "api_key"  # type: ignore[attr-defined]
        assert captured["requested_model"] == "chat-default"
        assert captured["effective_model"] == "chat-fast"

        # SSE streaming request: chat-default -> chat-fast
        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json={
                "model": "chat-default",
                "messages": [{"role": "user", "content": "Remap SSE request"}],
                "stream": True,
            },
            headers={"Authorization": f"Bearer {product_jwt}"},
        ) as sse_resp:
            assert sse_resp.status_code == 200
            data_lines = [
                line.removeprefix("data: ").strip()
                async for line in sse_resp.aiter_lines()
                if line.startswith("data: ")
            ]
        chunks = [json.loads(line) for line in data_lines[:-1]]
        assert all(chunk["model"] == "chat-fast" for chunk in chunks)

        # Disallowed model even if listed in model_alias_remapping still returns 403
        disallowed_resp = await client.post(
            "/v1/chat/completions",
            json={
                "model": "chat-premium",
                "messages": [{"role": "user", "content": "Must still be 403"}],
            },
            headers={"Authorization": f"Bearer {product_jwt}"},
        )
        assert disallowed_resp.status_code == 403
        assert len(recorder.requests) == 3


async def test_hs256_algorithm_confusion_with_rsa_public_key_is_rejected() -> None:
    import base64
    import hashlib
    import hmac

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    keypair = generate_rsa_keypair(seed="alg-confusion")
    header_b64 = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    claims_b64 = _b64url(
        json.dumps(
            {
                "sub": "attacker",
                "team": "platform-eng",
                "role": "admin",
                "iss": DEFAULT_ISSUER,
                "aud": DEFAULT_AUDIENCE,
                "exp": 9_999_999_999,
            }
        ).encode("utf-8")
    )
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    sig_b64 = _b64url(
        hmac.new(keypair.public_pem.encode("utf-8"), signing_input, hashlib.sha256).digest()
    )
    forged_token = f"{header_b64}.{claims_b64}.{sig_b64}"

    app, recorder = _make_gateway_and_recorder(
        jwt_jwks=keypair.jwks,
        jwt_hs256_enabled=True,
        jwt_hs256_secret=DEFAULT_HS256_SECRET,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),  # type: ignore[arg-type]
        base_url="http://control-plane",
    ) as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "chat-default", "messages": [{"role": "user", "content": "Forged"}]},
            headers={"Authorization": f"Bearer {forged_token}"},
        )

    assert resp.status_code == 401
    assert len(recorder.requests) == 0
