"""Security utilities for ACME protocol implementation."""

import base64
import hashlib
import ipaddress
import json
import secrets
from typing import Any, List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def generate_nonce() -> str:
    """Generate a cryptographically secure nonce for ACME protocol."""
    return secrets.token_urlsafe(16)


def generate_token() -> str:
    """Generate a cryptographically secure token for challenges."""
    return secrets.token_urlsafe(32)


def b64_encode(data: bytes) -> str:
    """Base64url encode data without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def calculate_jwk_thumbprint(public_jwk: dict[str, Any]) -> str:
    """
    Calculates the JWK thumbprint according to RFC 7638.
    """
    # Select required fields based on key type and sort them
    if public_jwk.get("kty") == "EC":
        required_fields = ["crv", "kty", "x", "y"]
    elif public_jwk.get("kty") == "RSA":
        required_fields = ["e", "kty", "n"]
    else:
        raise NotImplementedError(f"Thumbprint for kty '{public_jwk.get('kty')}' not supported.")

    canonical_jwk = {k: public_jwk[k] for k in sorted(required_fields)}

    # Create compact JSON string
    canonical_json = json.dumps(canonical_jwk, separators=(",", ":"), sort_keys=True)

    # Hash and encode
    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    return b64_encode(digest)


def get_key_authorization(token: str, public_jwk: dict[str, Any]) -> str:
    """Generate key authorization for ACME challenges."""
    thumbprint = calculate_jwk_thumbprint(public_jwk)
    return f"{token}.{thumbprint}"


def validate_csr(csr_der: bytes, order_identifiers: List[str], account_jwk: dict[str, Any]) -> None:
    """
    Validate a Certificate Signing Request according to RFC 8555 requirements.

    Args:
        csr_der: DER-encoded CSR bytes
        order_identifiers: List of identifier values from the order
        account_jwk: Account's public key in JWK format

    Raises:
        ValueError: If CSR validation fails
    """
    try:
        # Parse the CSR
        csr = x509.load_der_x509_csr(csr_der)

        # Extract public key from CSR
        csr_public_key = csr.public_key()

        # 1. Verify CSR public key is NOT the same as account key
        account_thumbprint = calculate_jwk_thumbprint(account_jwk)
        csr_jwk = _public_key_to_jwk(csr_public_key)
        csr_thumbprint = calculate_jwk_thumbprint(csr_jwk)

        if account_thumbprint == csr_thumbprint:
            raise ValueError("CSR public key must not be the same as account key")

        # 2. Extract identifiers from CSR
        csr_dns_names = set()

        # Check subject common name
        try:
            subject = csr.subject
            for attribute in subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    csr_dns_names.add(attribute.value.lower())
        except Exception:
            pass  # No subject or CN is optional

        # Check Subject Alternative Name extension
        try:
            san_ext = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_value = san_ext.value
            if hasattr(san_value, "__iter__"):
                for san in san_value:
                    if isinstance(san, x509.DNSName):
                        csr_dns_names.add(san.value.lower())
        except x509.ExtensionNotFound:
            pass  # SAN extension is optional

        # 3. Verify CSR identifiers match order identifiers exactly
        order_dns_names = {identifier.lower() for identifier in order_identifiers}

        if csr_dns_names != order_dns_names:
            raise ValueError(f"CSR identifiers {csr_dns_names} do not match order identifiers {order_dns_names}")

        # 4. Validate that no unauthorized extensions are present
        allowed_extensions = {
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            x509.oid.ExtensionOID.KEY_USAGE,
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
        }

        for extension in csr.extensions:
            if extension.oid not in allowed_extensions:
                raise ValueError(f"Unauthorized extension in CSR: {extension.oid}")

    except Exception as e:
        if isinstance(e, ValueError):
            raise
        raise ValueError(f"Failed to parse or validate CSR: {e}")


def _public_key_to_jwk(public_key: Any) -> dict[str, Any]:
    """Convert a cryptography public key to JWK format."""
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        if curve_name == "secp256r1":
            crv = "P-256"
        elif curve_name == "secp384r1":
            crv = "P-384"
        elif curve_name == "secp521r1":
            crv = "P-521"
        else:
            raise ValueError(f"Unsupported EC curve: {curve_name}")

        # Get coordinates
        numbers = public_key.public_numbers()
        x_bytes = numbers.x.to_bytes((public_key.curve.key_size + 7) // 8, "big")
        y_bytes = numbers.y.to_bytes((public_key.curve.key_size + 7) // 8, "big")

        return {"kty": "EC", "crv": crv, "x": b64_encode(x_bytes), "y": b64_encode(y_bytes)}
    elif isinstance(public_key, rsa.RSAPublicKey):
        rsa_numbers = public_key.public_numbers()
        n_bytes = rsa_numbers.n.to_bytes((rsa_numbers.n.bit_length() + 7) // 8, "big")
        e_bytes = rsa_numbers.e.to_bytes((rsa_numbers.e.bit_length() + 7) // 8, "big")

        return {"kty": "RSA", "n": b64_encode(n_bytes), "e": b64_encode(e_bytes)}
    else:
        raise ValueError(f"Unsupported public key type: {type(public_key)}")


def validate_ip_in_cidr_ranges(ip_address: str, cidr_ranges: str) -> bool:
    """
    Validate that an IP address is within allowed CIDR ranges.

    Args:
        ip_address: IP address to validate
        cidr_ranges: Comma-separated CIDR ranges (empty string allows all)

    Returns:
        True if IP is allowed, False otherwise
    """
    if not cidr_ranges.strip():
        return True  # Empty CIDR list allows all IPs

    try:
        ip = ipaddress.ip_address(ip_address)

        for cidr_range in cidr_ranges.split(","):
            cidr_range = cidr_range.strip()
            if not cidr_range:
                continue

            network = ipaddress.ip_network(cidr_range, strict=False)
            if ip in network:
                return True

        return False

    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False


def is_algorithm_allowed(algorithm: str, allowed_algorithms: List[str]) -> bool:
    """
    Check if a JWS algorithm is in the allowed list.

    Args:
        algorithm: Algorithm to check
        allowed_algorithms: List of allowed algorithms

    Returns:
        True if algorithm is allowed, False otherwise
    """
    # Explicitly block dangerous algorithms
    blocked_algorithms = {"none", "HS256", "HS384", "HS512"}

    if algorithm in blocked_algorithms:
        return False

    return algorithm in allowed_algorithms
