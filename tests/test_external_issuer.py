from __future__ import annotations

import os
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from acme_proxy.external_issuer import _write_openssl_csr_filter_wrapper


def _csr_pem(common_name: str, san_dns_names: list[str]) -> bytes:
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
    return csr.public_bytes(serialization.Encoding.PEM)


def test_openssl_csr_filter_wrapper_hides_duplicate_cn_san_from_acmesh_parser(tmp_path: Path) -> None:
    csr_path = tmp_path / "request.csr"
    wrapper_path = tmp_path / "openssl-filter.py"
    csr_path.write_bytes(_csr_pem("example.com", ["example.com", "www.example.com"]))
    _write_openssl_csr_filter_wrapper(wrapper_path)

    env = os.environ.copy()
    env["ACME_PROXY_REAL_OPENSSL"] = "openssl"
    env["ACME_PROXY_SIGNCSR_PATH"] = str(csr_path)
    result = subprocess.run(
        [str(wrapper_path), "req", "-noout", "-text", "-in", str(csr_path)],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )

    dns_lines = [line.strip() for line in result.stdout.splitlines() if line.lstrip().startswith("DNS:")]
    assert "DNS:www.example.com" in ", ".join(dns_lines)
    assert "DNS:example.com" not in ", ".join(dns_lines)
