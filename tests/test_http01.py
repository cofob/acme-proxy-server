from __future__ import annotations

import asyncio

import pytest

from acme_proxy import main
from acme_proxy.security import get_key_authorization


class FakeResponse:
    def __init__(self, text: str) -> None:
        self.status_code = 200
        self.text = text
        self.headers = {"content-type": "text/plain; charset=utf-8"}


class FakeAsyncClient:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, str]]] = []

    async def __aenter__(self) -> "FakeAsyncClient":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    async def get(self, url: str, headers: dict[str, str]) -> FakeResponse:
        self.calls.append((url, headers))
        return self.response


def test_verify_http01_challenge_uses_resolved_ip_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge_id = "challenge-1"
    authz_id = "authz-1"
    order_id = "order-1"
    domain = "rebinding.test"
    token = "token-1"
    account_jwk = {"kty": "RSA", "n": "abc", "e": "AQAB"}
    expected_content = get_key_authorization(token, account_jwk)
    fake_client = FakeAsyncClient(FakeResponse(expected_content))

    resources = {
        ("challenges", challenge_id): {"token": token, "status": "pending"},
        ("authorizations", authz_id): {
            "identifier": {"type": "dns", "value": domain},
            "status": "pending",
            "challenges": [{"url": f"https://acme.test/acme/chall/{challenge_id}"}],
        },
        ("orders", order_id): {
            "status": "pending",
            "authorizations": [f"https://acme.test/acme/authz/{authz_id}"],
        },
        ("orders", None): {order_id: {"authorizations": [f"https://acme.test/acme/authz/{authz_id}"]}},
    }

    async def fake_get_resource(resource_id: str | None, resource_type: str) -> object | None:
        return resources.get((resource_type, resource_id))

    async def fake_update_resource(resource_id: str, resource_type: str, new_obj: dict[str, object]) -> None:
        resources[(resource_type, resource_id)] = new_obj

    def fake_async_client(*args: object, **kwargs: object) -> FakeAsyncClient:
        return fake_client

    monkeypatch.setattr(main.state, "get_resource", fake_get_resource)
    monkeypatch.setattr(main.state, "update_resource", fake_update_resource)

    async def fake_resolve_http01_addresses(host: str) -> list[str]:
        return ["203.0.113.10"]

    monkeypatch.setattr(main, "resolve_http01_addresses", fake_resolve_http01_addresses)
    monkeypatch.setattr(main.httpx, "AsyncClient", fake_async_client)
    monkeypatch.setattr(main.settings, "ALLOWED_CHALLENGE_CIDR", "203.0.113.0/24")

    asyncio.run(main.verify_http01_challenge(challenge_id, authz_id, order_id, account_jwk))

    assert fake_client.calls
    assert fake_client.calls[0][0] == f"http://203.0.113.10:80/.well-known/acme-challenge/{token}"


def test_verify_http01_challenge_does_not_echo_raw_body_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    challenge_id = "challenge-2"
    authz_id = "authz-2"
    order_id = "order-2"
    domain = "validation.test"
    token = "token-2"
    account_jwk = {"kty": "RSA", "n": "abc", "e": "AQAB"}
    expected_content = get_key_authorization(token, account_jwk)
    marker = "TOP_SECRET_MARKER"
    fake_client = FakeAsyncClient(FakeResponse(marker))
    captured_updates: dict[tuple[str, str], dict[str, object]] = {}

    resources = {
        ("challenges", challenge_id): {"token": token, "status": "pending"},
        ("authorizations", authz_id): {
            "identifier": {"type": "dns", "value": domain},
            "status": "pending",
            "challenges": [{"url": f"https://acme.test/acme/chall/{challenge_id}"}],
        },
        ("orders", order_id): {
            "status": "pending",
            "authorizations": [f"https://acme.test/acme/authz/{authz_id}"],
        },
        ("orders", None): {order_id: {"authorizations": [f"https://acme.test/acme/authz/{authz_id}"]}},
    }

    async def fake_get_resource(resource_id: str | None, resource_type: str) -> object | None:
        return resources.get((resource_type, resource_id))

    async def fake_update_resource(resource_id: str, resource_type: str, new_obj: dict[str, object]) -> None:
        captured_updates[(resource_type, resource_id)] = new_obj

    def fake_async_client(*args: object, **kwargs: object) -> FakeAsyncClient:
        return fake_client

    monkeypatch.setattr(main.state, "get_resource", fake_get_resource)
    monkeypatch.setattr(main.state, "update_resource", fake_update_resource)

    async def fake_resolve_http01_addresses(host: str) -> list[str]:
        return ["203.0.113.11"]

    monkeypatch.setattr(main, "resolve_http01_addresses", fake_resolve_http01_addresses)
    monkeypatch.setattr(main.httpx, "AsyncClient", fake_async_client)
    monkeypatch.setattr(main.settings, "ALLOWED_CHALLENGE_CIDR", "203.0.113.0/24")

    asyncio.run(main.verify_http01_challenge(challenge_id, authz_id, order_id, account_jwk))

    challenge_error = captured_updates[("challenges", challenge_id)]["error"]
    assert isinstance(challenge_error, dict)
    assert marker not in challenge_error["detail"]
    assert expected_content not in challenge_error["detail"]
