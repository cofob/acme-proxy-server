from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from jose import jws
import pytest

from acme_proxy import auth, main
from acme_proxy.security import b64_encode
from acme_proxy.state import StateManager


@dataclass(frozen=True)
class AcmeSigningKey:
    private_jwk: dict[str, str]
    public_jwk: dict[str, str]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _new_ec_signing_key() -> AcmeSigningKey:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers
    coordinate_size = (private_key.curve.key_size + 7) // 8
    public_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64_encode(public_numbers.x.to_bytes(coordinate_size, "big")),
        "y": b64_encode(public_numbers.y.to_bytes(coordinate_size, "big")),
    }
    private_jwk = {
        **public_jwk,
        "d": b64_encode(private_numbers.private_value.to_bytes(coordinate_size, "big")),
    }
    return AcmeSigningKey(private_jwk=private_jwk, public_jwk=public_jwk)


def _signed_body(
    client: TestClient,
    path: str,
    key: AcmeSigningKey,
    payload: dict[str, object] | None,
    kid: str | None = None,
) -> dict[str, str]:
    nonce_response = client.head("/acme/new-nonce")
    assert nonce_response.status_code == 204
    nonce = nonce_response.headers["Replay-Nonce"]

    protected: dict[str, object] = {
        "nonce": nonce,
        "url": f"http://localhost:8000{path}",
        "alg": "ES256",
    }
    if kid is None:
        protected["jwk"] = key.public_jwk
    else:
        protected["kid"] = kid

    compact = jws.sign(
        payload if payload is not None else b"",
        key.private_jwk,
        headers=protected,
        algorithm="ES256",
    )
    protected_b64, payload_b64, signature_b64 = compact.split(".")
    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    }


def _post_acme(
    client: TestClient,
    path: str,
    key: AcmeSigningKey,
    payload: dict[str, object] | None,
    kid: str | None = None,
) -> HttpxResponse:
    return client.post(
        path,
        json=_signed_body(client, path, key, payload, kid),
        headers={"content-type": "application/jose+json"},
    )


def _certbot_style_csr_der(common_name: str, san_dns_names: list[str]) -> bytes:
    csr_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]),
            critical=False,
        )
        .sign(csr_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def _certificate_for_csr(csr_pem: str) -> str:
    csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ACME Proxy Test Issuer")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    cert = builder.add_extension(san.value, critical=san.critical).sign(issuer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_acme_account_order_challenge_finalize_and_download_e2e(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "state.json"
    cert_storage_path = tmp_path / "certs"
    cert_storage_path.mkdir()
    test_state = StateManager(str(state_path))

    monkeypatch.setattr(auth, "state", test_state)
    monkeypatch.setattr(main, "state", test_state)
    monkeypatch.setattr(main.settings, "SERVER_URL", "http://localhost:8000")
    monkeypatch.setattr(main.settings, "BASE_DOMAIN_SUFFIX", "example.com")
    monkeypatch.setattr(main.settings, "CERT_STORAGE_PATH", str(cert_storage_path))

    async def fake_verify_http01_challenge(
        challenge_id: str,
        authz_id: str,
        order_id: str,
        account_jwk: dict[str, object],
    ) -> None:
        assert account_jwk
        challenge_obj = await test_state.get_resource(challenge_id, "challenges")
        authz_obj = await test_state.get_resource(authz_id, "authorizations")
        order_obj = await test_state.get_resource(order_id, "orders")
        assert isinstance(challenge_obj, dict)
        assert isinstance(authz_obj, dict)
        assert isinstance(order_obj, dict)

        challenge_obj["status"] = "valid"
        authz_obj["status"] = "valid"
        order_obj["status"] = "ready"
        await test_state.update_resource(challenge_id, "challenges", challenge_obj)
        await test_state.update_resource(authz_id, "authorizations", authz_obj)
        await test_state.update_resource(order_id, "orders", order_obj)

    async def fake_issue_certificate_with_acmesh(identifiers: list[str], csr_pem: str | None = None) -> str:
        assert identifiers == ["example.com"]
        assert csr_pem is not None
        return _certificate_for_csr(csr_pem)

    monkeypatch.setattr(main, "verify_http01_challenge", fake_verify_http01_challenge)
    monkeypatch.setattr(main, "issue_certificate_with_acmesh", fake_issue_certificate_with_acmesh)

    client = TestClient(main.app, base_url="http://localhost:8000")
    account_key = _new_ec_signing_key()

    directory_response = client.get("/directory")
    assert directory_response.status_code == 200
    directory = directory_response.json()
    assert directory["newNonce"] == "http://localhost:8000/acme/new-nonce"
    assert directory["newAccount"] == "http://localhost:8000/acme/new-account"
    assert directory["newOrder"] == "http://localhost:8000/acme/new-order"

    account_response = _post_acme(
        client,
        "/acme/new-account",
        account_key,
        {"termsOfServiceAgreed": True, "contact": ["mailto:admin@example.com"]},
    )
    assert account_response.status_code == 201
    kid = account_response.headers["Location"]

    order_response = _post_acme(
        client,
        "/acme/new-order",
        account_key,
        {"identifiers": [{"type": "dns", "value": "example.com"}]},
        kid,
    )
    assert order_response.status_code == 201
    order_url = order_response.headers["Location"]
    order = order_response.json()
    assert order["status"] == "pending"

    authz_path = urlsplit(order["authorizations"][0]).path
    authz_response = _post_acme(client, authz_path, account_key, None, kid)
    assert authz_response.status_code == 200
    authz = authz_response.json()
    assert authz["status"] == "pending"

    challenge_path = urlsplit(authz["challenges"][0]["url"]).path
    challenge_response = _post_acme(client, challenge_path, account_key, {}, kid)
    assert challenge_response.status_code == 200
    assert challenge_response.json()["status"] == "processing"

    order_path = urlsplit(order_url).path
    ready_order_response = _post_acme(client, order_path, account_key, None, kid)
    assert ready_order_response.status_code == 200
    assert ready_order_response.json()["status"] == "ready"

    csr_der = _certbot_style_csr_der("example.com", ["example.com"])
    finalize_path = urlsplit(order["finalize"]).path
    finalize_response = _post_acme(client, finalize_path, account_key, {"csr": _b64url(csr_der)}, kid)
    assert finalize_response.status_code == 200
    assert finalize_response.json()["status"] == "processing"

    valid_order_response = _post_acme(client, order_path, account_key, None, kid)
    assert valid_order_response.status_code == 200
    valid_order = valid_order_response.json()
    assert valid_order["status"] == "valid"
    cert_path = urlsplit(valid_order["certificate"]).path

    cert_response = _post_acme(client, cert_path, account_key, None, kid)
    assert cert_response.status_code == 200
    assert cert_response.headers["content-type"].startswith("application/pem-certificate-chain")
    assert "-----BEGIN CERTIFICATE-----" in cert_response.text
