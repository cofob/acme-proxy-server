from __future__ import annotations

import asyncio

import pytest
from fastapi import Response

from acme_proxy import main


def test_new_order_marks_wildcard_authorization(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_authorizations: list[dict[str, object]] = []

    async def fake_get_account_by_kid(kid: str) -> dict[str, object] | None:
        return {"kid": kid, "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"}}

    async def fake_add_challenge(challenge_id: str, challenge_obj: dict[str, object]) -> None:
        return None

    async def fake_add_authorization(authz_id: str, authz_obj: dict[str, object]) -> None:
        captured_authorizations.append(authz_obj)

    async def fake_add_order(order_id: str, order_obj: dict[str, object]) -> None:
        return None

    async def fake_add_replay_nonce(response: Response) -> None:
        return None

    monkeypatch.setattr(main.state, "get_account_by_kid", fake_get_account_by_kid)
    monkeypatch.setattr(main.state, "add_challenge", fake_add_challenge)
    monkeypatch.setattr(main.state, "add_authorization", fake_add_authorization)
    monkeypatch.setattr(main.state, "add_order", fake_add_order)
    monkeypatch.setattr(main, "add_replay_nonce", fake_add_replay_nonce)
    monkeypatch.setattr(main.settings, "BASE_DOMAIN_SUFFIX", "example.com")

    asyncio.run(
        main.new_order(
            Response(),
            {
                "payload": {
                    "identifiers": [{"type": "dns", "value": "*.example.com"}],
                },
                "kid": "https://acme.test/acme/acct/account-1",
                "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
            },
        )
    )

    assert captured_authorizations
    authorization = captured_authorizations[0]
    assert authorization["wildcard"] is True
    identifier = authorization["identifier"]
    assert isinstance(identifier, dict)
    assert identifier["value"] == "example.com"
