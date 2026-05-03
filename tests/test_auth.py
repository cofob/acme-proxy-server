from __future__ import annotations

import asyncio
import base64
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from acme_proxy import auth
from acme_proxy import main


def _b64url_json(value: dict[str, object]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("utf-8")


def _request(body: dict[str, object]) -> Request:
    body_bytes = json.dumps(body).encode("utf-8")

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": body_bytes}

    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/acme/new-account",
            "headers": [(b"content-type", b"application/jose+json")],
            "scheme": "https",
            "server": ("acme.test", 443),
            "client": ("127.0.0.1", 12345),
        },
        receive,
    )


def test_verify_jws_rejects_protected_header_with_both_jwk_and_kid(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_use_nonce(nonce: str) -> bool:
        return True

    verify_called = False

    def fake_verify(*args: object, **kwargs: object) -> None:
        nonlocal verify_called
        verify_called = True

    monkeypatch.setattr(auth.state, "use_nonce", fake_use_nonce)
    monkeypatch.setattr(auth.jws, "verify", fake_verify)

    request = _request(
        {
            "protected": _b64url_json(
                {
                    "nonce": "nonce-1",
                    "url": "https://acme.test/acme/new-account",
                    "alg": "ES256",
                    "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
                    "kid": "https://acme.test/acme/acct/foreign",
                }
            ),
            "payload": "",
            "signature": "signature",
        }
    )

    with pytest.raises(HTTPException):
        asyncio.run(auth.verify_jws(request))

    assert not verify_called


def test_bad_nonce_response_includes_replay_nonce_header(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_use_nonce(nonce: str) -> bool:
        return False

    async def fake_add_nonce(nonce: str) -> None:
        return None

    monkeypatch.setattr(auth.state, "use_nonce", fake_use_nonce)
    monkeypatch.setattr(auth.state, "add_nonce", fake_add_nonce)

    client = TestClient(main.app)
    response = client.post(
        "/acme/new-account",
        headers={"Content-Type": "application/jose+json"},
        json={
            "protected": _b64url_json(
                {
                    "nonce": "stale-nonce",
                    "url": "http://localhost:8000/acme/new-account",
                    "alg": "ES256",
                    "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
                }
            ),
            "payload": "",
            "signature": "signature",
        },
    )

    assert response.status_code == 400
    assert response.headers["Replay-Nonce"]
    assert response.json()["detail"]["type"] == "urn:ietf:params:acme:error:badNonce"
