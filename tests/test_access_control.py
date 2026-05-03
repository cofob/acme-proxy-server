from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import BackgroundTasks, HTTPException, Response

from acme_proxy import main


def _problem_order(order_id: str, owner_kid: str) -> dict[str, object]:
    return {
        "status": "ready",
        "identifiers": [{"type": "dns", "value": "example.com"}],
        "authorizations": [f"https://acme.test/acme/authz/{order_id}-authz"],
        "finalize": f"https://acme.test/acme/order/{order_id}/finalize",
        "account": owner_kid,
    }


def _problem_authorization(authz_id: str, owner_kid: str) -> dict[str, object]:
    return {
        "identifier": {"type": "dns", "value": "example.com"},
        "status": "valid",
        "challenges": [
            {
                "type": "http-01",
                "url": f"https://acme.test/acme/chall/{authz_id}-chall",
                "status": "pending",
                "token": "token-1",
            }
        ],
        "account": owner_kid,
    }


def _problem_challenge(challenge_id: str, owner_kid: str) -> dict[str, object]:
    return {
        "type": "http-01",
        "url": f"https://acme.test/acme/chall/{challenge_id}",
        "status": "pending",
        "token": "token-1",
        "account": owner_kid,
    }


def _patch_noop_replay_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_add_replay_nonce(response: Response) -> None:
        return None

    monkeypatch.setattr(main, "add_replay_nonce", fake_add_replay_nonce)


def test_get_order_rejects_foreign_account(monkeypatch: pytest.MonkeyPatch) -> None:
    order_id = "order-1"
    owner_kid = "https://acme.test/acme/acct/owner"
    requester_kid = "https://acme.test/acme/acct/requester"
    order_obj = _problem_order(order_id, owner_kid)

    async def fake_get_resource(resource_id: str | None, resource_type: str) -> object | None:
        if resource_type == "orders" and resource_id == order_id:
            return order_obj
        return None

    monkeypatch.setattr(main.state, "get_resource", fake_get_resource)
    _patch_noop_replay_nonce(monkeypatch)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            main.get_order(
                order_id,
                Response(),
                {
                    "payload": {},
                    "kid": requester_kid,
                    "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
                },
            )
        )

    assert excinfo.value.status_code == 404


def test_get_authorization_rejects_foreign_account(monkeypatch: pytest.MonkeyPatch) -> None:
    authz_id = "authz-1"
    owner_kid = "https://acme.test/acme/acct/owner"
    requester_kid = "https://acme.test/acme/acct/requester"
    authz_obj = _problem_authorization(authz_id, owner_kid)

    async def fake_get_resource(resource_id: str | None, resource_type: str) -> object | None:
        if resource_type == "authorizations" and resource_id == authz_id:
            return authz_obj
        return None

    monkeypatch.setattr(main.state, "get_resource", fake_get_resource)
    _patch_noop_replay_nonce(monkeypatch)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            main.get_authorization(
                authz_id,
                Response(),
                {
                    "payload": {},
                    "kid": requester_kid,
                    "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
                },
            )
        )

    assert excinfo.value.status_code == 404


def test_respond_to_challenge_rejects_foreign_account(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge_id = "challenge-1"
    authz_id = "authz-1"
    order_id = "order-1"
    owner_kid = "https://acme.test/acme/acct/owner"
    requester_kid = "https://acme.test/acme/acct/requester"
    challenge_obj = _problem_challenge(challenge_id, owner_kid)
    authz_obj = {
        "identifier": {"type": "dns", "value": "example.com"},
        "status": "pending",
        "challenges": [challenge_obj],
        "account": owner_kid,
    }
    order_obj = {
        "status": "pending",
        "identifiers": [{"type": "dns", "value": "example.com"}],
        "authorizations": [f"https://acme.test/acme/authz/{authz_id}"],
        "finalize": f"https://acme.test/acme/order/{order_id}/finalize",
        "account": owner_kid,
    }
    resources = {
        ("challenges", challenge_id): challenge_obj,
        ("authorizations", authz_id): authz_obj,
        ("orders", order_id): order_obj,
        ("orders", None): {order_id: order_obj},
    }

    async def fake_get_resource(resource_id: str | None, resource_type: str) -> object | None:
        return resources.get((resource_type, resource_id))

    async def fake_get_account_by_kid(kid: str) -> dict[str, object] | None:
        if kid == requester_kid:
            return {"jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}}
        return None

    monkeypatch.setattr(main.state, "get_resource", fake_get_resource)
    monkeypatch.setattr(main.state, "get_account_by_kid", fake_get_account_by_kid)
    _patch_noop_replay_nonce(monkeypatch)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            main.respond_to_challenge(
                challenge_id,
                Response(),
                BackgroundTasks(),
                {
                    "payload": {},
                    "kid": requester_kid,
                    "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
                },
            )
        )

    assert excinfo.value.status_code == 404


def test_download_cert_rejects_foreign_account(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cert_id = "cert-1"
    owner_kid = "https://acme.test/acme/acct/owner"
    requester_kid = "https://acme.test/acme/acct/requester"
    cert_path = tmp_path / f"{cert_id}.pem"
    cert_path.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", encoding="utf-8")

    async def fake_get_resource(resource_id: str | None, resource_type: str) -> object | None:
        if resource_type == "certificates" and resource_id == cert_id:
            return {"account": owner_kid, "path": str(cert_path)}
        return None

    monkeypatch.setattr(main.settings, "CERT_STORAGE_PATH", str(tmp_path))
    monkeypatch.setattr(main.state, "get_resource", fake_get_resource)
    _patch_noop_replay_nonce(monkeypatch)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            main.download_cert(
                cert_id,
                Response(),
                {
                    "payload": {},
                    "kid": requester_kid,
                    "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
                },
            )
        )

    assert excinfo.value.status_code == 404
