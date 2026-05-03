from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acme_proxy.security import _public_key_to_jwk, validate_csr


def _account_jwk() -> dict[str, object]:
    account_key = ec.generate_private_key(ec.SECP256R1())
    return _public_key_to_jwk(account_key.public_key())


def _csr_der(common_name: str | None, san_dns_names: list[str] | None = None) -> bytes:
    csr_key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder()

    if common_name is not None:
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))

    if san_dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]),
            critical=False,
        )

    csr = builder.sign(csr_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.DER)


def test_validate_csr_accepts_duplicate_dns_identifier_across_cn_and_san() -> None:
    csr_der = _csr_der("example.com", ["example.com"])

    validate_csr(csr_der, ["example.com"], _account_jwk())


def test_validate_csr_accepts_dns_identifier_from_common_name() -> None:
    csr_der = _csr_der("example.com")

    validate_csr(csr_der, ["example.com"], _account_jwk())
