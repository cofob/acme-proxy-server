import asyncio
import base64
import logging
import os
import socket
import stat
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Response
from fastapi.responses import RedirectResponse

from acme_proxy.auth import verify_jws
from acme_proxy.config import settings
from acme_proxy.external_issuer import issue_certificate_with_acmesh
from acme_proxy.models import (
    Account,
    Authorization,
    Challenge,
    Directory,
    FinalizePayload,
    NewAccountPayload,
    NewOrderPayload,
    Order,
    Problem,
)
from acme_proxy.security import (
    generate_nonce,
    generate_token,
    get_key_authorization,
    validate_csr,
    validate_ip_in_cidr_ranges,
    AcmeProblemError,
    normalize_dns_identifier,
)
from acme_proxy.state import state
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI()

ORDER_EXPIRES_AFTER = timedelta(days=7)
AUTHORIZATION_EXPIRES_AFTER = timedelta(days=30)


# --- Helper Functions ---
def full_url_for(path: str) -> str:
    return f"{settings.SERVER_URL.rstrip('/')}/{path.lstrip('/')}"


def acme_timestamp_after(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def is_owned_by(resource: dict[str, Any], kid: str) -> bool:
    return resource.get("account") == kid


def dns_identifier_for_authorization(identifier: str) -> tuple[str, bool]:
    normalized = normalize_dns_identifier(identifier)
    if normalized.startswith("*."):
        return normalized[2:], True
    return normalized, False


def is_identifier_allowed(identifier: str) -> bool:
    if not settings.BASE_DOMAIN_SUFFIX:
        return True

    authz_identifier, _ = dns_identifier_for_authorization(identifier)
    allowed_suffix = normalize_dns_identifier(settings.BASE_DOMAIN_SUFFIX)
    return authz_identifier == allowed_suffix or authz_identifier.endswith(f".{allowed_suffix}")


def http_url_host(ip_address: str) -> str:
    if ":" in ip_address:
        return f"[{ip_address}]"
    return ip_address


async def resolve_http01_addresses(domain: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        address_info = await loop.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"Failed to resolve domain {domain}") from e

    addresses: list[str] = []
    seen: set[str] = set()
    for info in address_info:
        ip_address = info[4][0]
        if ip_address not in seen:
            seen.add(ip_address)
            addresses.append(ip_address)

    if not addresses:
        raise ValueError(f"Domain {domain} did not resolve to any address")

    if settings.ALLOWED_CHALLENGE_CIDR:
        blocked_addresses = [
            ip_address
            for ip_address in addresses
            if not validate_ip_in_cidr_ranges(ip_address, settings.ALLOWED_CHALLENGE_CIDR)
        ]
        if blocked_addresses:
            raise ValueError(
                f"Domain {domain} resolves outside the allowed CIDR ranges: {settings.ALLOWED_CHALLENGE_CIDR}"
            )

    return addresses


async def find_parent_ids_for_challenge(challenge_id: str, kid: str) -> tuple[str | None, str | None]:
    challenge_obj = await state.get_resource(challenge_id, "challenges")
    if challenge_obj and is_owned_by(challenge_obj, kid):
        authz_id = challenge_obj.get("authorization")
        order_id = challenge_obj.get("order")
        if isinstance(authz_id, str) and isinstance(order_id, str):
            return authz_id, order_id

    for oid, order_obj in (await state.get_resource(None, "orders")).items():
        if not is_owned_by(order_obj, kid):
            continue
        for auth_url in order_obj["authorizations"]:
            aid = auth_url.split("/")[-1]
            auth_obj = await state.get_resource(aid, "authorizations")
            if not auth_obj or not is_owned_by(auth_obj, kid):
                continue
            if any(challenge["url"].endswith(challenge_id) for challenge in auth_obj["challenges"]):
                return aid, oid
    return None, None


async def get_owned_certificate(cert_id: str, kid: str) -> dict[str, Any] | None:
    cert_obj = await state.get_resource(cert_id, "certificates")
    if cert_obj:
        if is_owned_by(cert_obj, kid):
            return cert_obj
        return None

    cert_url = full_url_for(f"acme/cert/{cert_id}")
    for order_id, order_obj in (await state.get_resource(None, "orders")).items():
        if is_owned_by(order_obj, kid) and order_obj.get("certificate") == cert_url:
            return {
                "account": kid,
                "order": order_id,
                "path": str(Path(settings.CERT_STORAGE_PATH) / f"{cert_id}.pem"),
            }
    return None


# Public key equality helper (module-level with full typing for mypy)
type PublicKeyTypes = RSAPublicKey | EllipticCurvePublicKey


def public_keys_equal(a: PublicKeyTypes, b: PublicKeyTypes) -> bool:
    if isinstance(a, rsa.RSAPublicKey) and isinstance(b, rsa.RSAPublicKey):
        return a.public_numbers() == b.public_numbers()
    if isinstance(a, ec.EllipticCurvePublicKey) and isinstance(b, ec.EllipticCurvePublicKey):
        return (
            a.curve.name == b.curve.name
            and a.public_numbers().x == b.public_numbers().x
            and a.public_numbers().y == b.public_numbers().y
        )
    return False


async def add_replay_nonce(response: Response) -> None:
    nonce = generate_nonce()
    await state.add_nonce(nonce)
    response.headers["Replay-Nonce"] = nonce
    response.headers["Link"] = f'<{full_url_for("directory")}>;rel="index"'
    # RFC 8555: CORS support for browser-based clients
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, HEAD"


# --- HTTP-01 Challenge Verification ---
async def verify_http01_challenge(challenge_id: str, authz_id: str, order_id: str, account_jwk: dict[str, Any]) -> None:
    logger.info(f"Starting HTTP-01 verification for challenge {challenge_id}")
    challenge_obj = await state.get_resource(challenge_id, "challenges")
    authz_obj = await state.get_resource(authz_id, "authorizations")
    order_obj = await state.get_resource(order_id, "orders")

    if not all([challenge_obj, authz_obj, order_obj]):
        logger.error("Could not find all necessary resources for verification.")
        return

    domain = authz_obj["identifier"]["value"]
    token = challenge_obj["token"]
    expected_content = get_key_authorization(token, account_jwk)

    try:
        approved_addresses = await resolve_http01_addresses(domain)
        ip_address = approved_addresses[0]
        logger.info(f"Resolved {domain} to approved HTTP-01 address {ip_address}")

        # ACME HTTP-01 challenge MUST be served on port 80 per RFC 8555. Connect to
        # the prevalidated address so a second DNS lookup cannot change the target.
        url = f"http://{http_url_host(ip_address)}:80/.well-known/acme-challenge/{token}"

        # Security: Use strict HTTP client configuration
        timeout_config = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=10.0)

        async with httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            timeout=timeout_config,
            limits=httpx.Limits(max_keepalive_connections=0),  # Disable connection reuse
        ) as client:
            # Perform the HTTP-01 challenge request
            response = await client.get(
                url,
                headers={
                    "Host": domain,
                    "User-Agent": "ACME-Proxy/1.0 HTTP-01-Validator",
                    "Accept": "text/plain, */*;q=0.1",
                },
            )

        # RFC 8555: Must be exactly 200 status
        if response.status_code != 200:
            raise Exception(f"HTTP-01 challenge failed: expected status 200, got {response.status_code}")

        # RFC 8555: Validate content exactly matches key authorization
        response_content = response.text.strip()
        if response_content != expected_content:
            raise Exception("HTTP-01 challenge content mismatch")

        # Validate Content-Type if present (should be text/plain)
        content_type = response.headers.get("content-type", "").lower()
        if content_type and not content_type.startswith("text/plain"):
            logger.warning(f"Non-standard Content-Type for HTTP-01 response: {content_type}")

        logger.info(f"HTTP-01 validation successful for {domain}")
        challenge_obj["status"] = "valid"
        challenge_obj["validated"] = datetime.now(timezone.utc).isoformat()
        await state.update_resource(challenge_id, "challenges", challenge_obj)

        authz_obj["status"] = "valid"
        authz_obj["expires"] = acme_timestamp_after(AUTHORIZATION_EXPIRES_AFTER)
        await state.update_resource(authz_id, "authorizations", authz_obj)

        # Check if all authorizations for the order are now valid
        all_valid = True
        for authz_url in order_obj["authorizations"]:
            authz_id_to_check = authz_url.split("/")[-1]
            authz_to_check = await state.get_resource(authz_id_to_check, "authorizations")
            if not authz_to_check or authz_to_check.get("status") != "valid":
                all_valid = False
                break

        if all_valid:
            logger.info(f"All authorizations for order {order_id} are valid. Order is ready.")
            order_obj["status"] = "ready"
            await state.update_resource(order_id, "orders", order_obj)

    except Exception as e:
        logger.warning(f"HTTP-01 validation failed for {domain}: {e}")
        challenge_obj["status"] = "invalid"
        authz_obj["status"] = "invalid"
        order_obj["status"] = "invalid"
        error = Problem(type="urn:ietf:params:acme:error:unauthorized", detail="HTTP-01 validation failed", status=403)
        challenge_obj["error"] = error.model_dump(by_alias=True, exclude_none=True)
        order_obj["error"] = error.model_dump(by_alias=True, exclude_none=True)
        await state.update_resource(challenge_id, "challenges", challenge_obj)
        await state.update_resource(authz_id, "authorizations", authz_obj)
        await state.update_resource(order_id, "orders", order_obj)


# --- Certificate Issuance via acme.sh ---
async def finalize_and_issue_cert(order_id: str, csr_pem: str, csr_der: bytes, account_jwk: dict[str, Any]) -> None:
    logger.info(f"Starting finalization for order {order_id}")
    order_obj_dict = await state.get_resource(order_id, "orders")

    try:
        # RFC 8555: Validate CSR according to security requirements
        order_identifiers = [ident["value"] for ident in order_obj_dict["identifiers"]]

        # Fail-fast if new-order accidentally contained duplicates (defense-in-depth)
        if len(order_identifiers) != len({normalize_dns_identifier(i) for i in order_identifiers}):
            raise AcmeProblemError(
                problem_type="urn:ietf:params:acme:error:rejectedIdentifier",
                detail="One or more identifiers are duplicated",
                status=400,
            )

        try:
            validate_csr(csr_der, order_identifiers, account_jwk)
            logger.info(f"CSR validation successful for order {order_id}")
        except AcmeProblemError:
            # Re-raise structured ACME errors untouched
            raise

        # Extract identifiers exactly as validated from the CSR
        identifiers_to_issue = [ident["value"] for ident in order_obj_dict["identifiers"]]
        # Deduplicate while preserving order for stable file naming
        seen: set[str] = set()
        unique_identifiers: list[str] = []
        for name in identifiers_to_issue:
            key = normalize_dns_identifier(name)
            if key not in seen:
                seen.add(key)
                unique_identifiers.append(name)

        # Use the provided CSR to ensure the certificate matches the client's key
        cert_content = await issue_certificate_with_acmesh(unique_identifiers, csr_pem=csr_pem)

        # Verify issued leaf certificate public key matches CSR public key
        csr_obj = x509.load_der_x509_csr(csr_der)
        csr_pub_any = csr_obj.public_key()

        # Parse all certificates in the returned fullchain and pick the one that matches CSR public key
        pem_certs: list[bytes] = []
        current: list[str] = []
        for line in cert_content.splitlines():
            current.append(line)
            if line.strip() == "-----END CERTIFICATE-----":
                pem_certs.append("\n".join(current).encode())
                current = []
        if not pem_certs:
            raise Exception("No PEM certificates found in returned fullchain content")

        # Load first as default, but search for matching pubkey
        candidate_cert = x509.load_pem_x509_certificate(pem_certs[0])
        leaf_pub_any = candidate_cert.public_key()

        # Narrow types for mypy and validate supported key types
        if not isinstance(csr_pub_any, (RSAPublicKey, EllipticCurvePublicKey)):
            raise Exception(f"Unsupported CSR public key type: {type(csr_pub_any)}")
        if not isinstance(leaf_pub_any, (RSAPublicKey, EllipticCurvePublicKey)):
            raise Exception(f"Unsupported certificate public key type: {type(leaf_pub_any)}")
        csr_pub: PublicKeyTypes = csr_pub_any

        # Try to find a certificate whose pubkey equals CSR pubkey
        matching_pub_found = False
        for pem in pem_certs:
            try:
                cert = x509.load_pem_x509_certificate(pem)
                cert_pub_any = cert.public_key()
                if not isinstance(cert_pub_any, (RSAPublicKey, EllipticCurvePublicKey)):
                    continue
                cert_pub: PublicKeyTypes = cert_pub_any
                if public_keys_equal(csr_pub, cert_pub):
                    matching_pub_found = True
                    break
            except Exception:
                continue

        if not matching_pub_found:
            raise Exception("Issued certificate public key does not match CSR public key")

        # Store the certificate with secure file permissions
        cert_id = str(uuid.uuid4())
        cert_path = Path(settings.CERT_STORAGE_PATH) / f"{cert_id}.pem"

        # Create file with restrictive permissions (owner read/write only)
        # Use os.open() with specific flags to ensure secure creation
        fd = os.open(cert_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(cert_content)
        except:
            os.close(fd)  # Ensure fd is closed if fdopen fails
            raise

        # Update order to valid
        order_obj_dict["status"] = "valid"
        order_obj_dict.setdefault("expires", acme_timestamp_after(ORDER_EXPIRES_AFTER))
        order_obj_dict["certificate"] = full_url_for(f"acme/cert/{cert_id}")
        await state.add_certificate(
            cert_id,
            {
                "account": order_obj_dict["account"],
                "order": order_id,
                "path": str(cert_path),
            },
        )
        await state.update_resource(order_id, "orders", order_obj_dict)
        logger.info(f"Certificate for order {order_id} issued and stored at {cert_path}")

    except AcmeProblemError as e:
        logger.error(f"Finalization failed for order {order_id}: {e.detail}")
        order_obj_dict["status"] = "invalid"
        error = Problem(type=e.problem_type, detail=e.detail, status=e.status)
        order_obj_dict["error"] = error.model_dump(by_alias=True, exclude_none=True)
        await state.update_resource(order_id, "orders", order_obj_dict)
    except Exception as e:
        logger.error(f"Finalization failed for order {order_id}: {e}")
        order_obj_dict["status"] = "invalid"
        error = Problem(type="urn:ietf:params:acme:error:serverInternal", detail=str(e), status=500)
        order_obj_dict["error"] = error.model_dump(by_alias=True, exclude_none=True)
        await state.update_resource(order_id, "orders", order_obj_dict)


# --- ACME Endpoints ---


@app.get("/directory", response_model=Directory, response_model_exclude_none=True)
async def get_directory(response: Response) -> Directory:
    await add_replay_nonce(response)
    dir_obj = Directory(
        new_nonce=full_url_for("acme/new-nonce"),
        new_account=full_url_for("acme/new-account"),
        new_order=full_url_for("acme/new-order"),
        revoke_cert=None,
        key_change=None,
    )
    return dir_obj


@app.api_route("/acme/new-nonce", methods=["GET", "HEAD"])
async def new_nonce(response: Response) -> Response:
    await add_replay_nonce(response)
    # RFC 8555: Prevent caching of nonce responses to avoid replay attacks
    response.headers["Cache-Control"] = "no-store"
    response.status_code = 204
    return response


@app.post(
    "/acme/new-account",
    status_code=201,
    response_model=Account,
    response_model_exclude_none=True,
)
async def new_account(response: Response, jws_data: dict[str, Any] = Depends(verify_jws)) -> Account:
    payload = NewAccountPayload(**jws_data["payload"])
    public_jwk = jws_data["jwk"]

    existing_account = await state.get_account_by_key(public_jwk)
    if existing_account:
        response.status_code = 200
        response.headers["Location"] = existing_account["kid"]
        await add_replay_nonce(response)
        return Account(**existing_account["obj"])

    if payload.only_return_existing:
        raise HTTPException(
            status_code=400,
            detail=Problem(
                type="urn:ietf:params:acme:error:accountDoesNotExist",
                detail="No account exists with this key",
                status=400,
            ).model_dump(by_alias=True, exclude_none=True),
        )

    account_id = str(uuid.uuid4())
    kid = full_url_for(f"acme/acct/{account_id}")

    account_obj = Account(
        contact=payload.contact,
        termsOfServiceAgreed=payload.terms_of_service_agreed,
        orders=full_url_for(f"acme/acct/{account_id}/orders"),
    )
    await state.add_account(kid, public_jwk, account_obj.model_dump(by_alias=True, exclude_none=True))

    response.headers["Location"] = kid
    await add_replay_nonce(response)
    return account_obj


@app.post(
    "/acme/new-order",
    status_code=201,
    response_model=Order,
    response_model_exclude_none=True,
)
async def new_order(response: Response, jws_data: dict[str, Any] = Depends(verify_jws)) -> Order:
    payload = NewOrderPayload(**jws_data["payload"])
    kid = jws_data["kid"]
    account = await state.get_account_by_kid(kid)
    if not account:
        raise HTTPException(status_code=403, detail="Account not found")

    # Validate identifiers
    for ident in payload.identifiers:
        if ident.type != "dns":
            raise HTTPException(
                status_code=400,
                detail=Problem(
                    type="urn:ietf:params:acme:error:unsupportedIdentifier",
                    detail=f"Identifier type {ident.type} is not supported.",
                    status=400,
                ).model_dump(by_alias=True, exclude_none=True),
            )
        if not is_identifier_allowed(ident.value):
            raise HTTPException(
                status_code=403,
                detail=Problem(
                    type="urn:ietf:params:acme:error:rejectedIdentifier",
                    detail=f"Identifier {ident.value} is not allowed.",
                    status=403,
                ).model_dump(by_alias=True, exclude_none=True),
            )

    # Reject duplicate identifiers in the order per ACME semantics
    values_lower = [normalize_dns_identifier(i.value) for i in payload.identifiers]
    if len(values_lower) != len(set(values_lower)):
        raise HTTPException(
            status_code=400,
            detail=Problem(
                type="urn:ietf:params:acme:error:rejectedIdentifier",
                detail="One or more identifiers are duplicated",
                status=400,
            ).model_dump(by_alias=True, exclude_none=True),
        )

    order_id = str(uuid.uuid4())
    auth_urls = []

    for ident in payload.identifiers:
        authz_id = str(uuid.uuid4())
        challenge_id = str(uuid.uuid4())
        authz_identifier, is_wildcard = dns_identifier_for_authorization(ident.value)
        authz_ident = ident.model_copy(update={"value": authz_identifier})

        challenge = Challenge(
            type="http-01",
            url=full_url_for(f"acme/chall/{challenge_id}"),
            token=generate_token(),
        )
        auth = Authorization(identifier=authz_ident, challenges=[challenge], wildcard=True if is_wildcard else None)

        challenge_obj = challenge.model_dump(by_alias=True, exclude_none=True)
        challenge_obj["account"] = kid
        challenge_obj["authorization"] = authz_id
        challenge_obj["order"] = order_id
        auth_obj = auth.model_dump(by_alias=True, exclude_none=True)
        auth_obj["account"] = kid
        auth_obj["order"] = order_id

        await state.add_challenge(challenge_id, challenge_obj)
        await state.add_authorization(authz_id, auth_obj)
        auth_urls.append(full_url_for(f"acme/authz/{authz_id}"))

    order = Order(
        identifiers=payload.identifiers,
        expires=acme_timestamp_after(ORDER_EXPIRES_AFTER),
        notBefore=payload.not_before,
        notAfter=payload.not_after,
        authorizations=auth_urls,
        finalize=full_url_for(f"acme/order/{order_id}/finalize"),
    )

    order_obj = order.model_dump(by_alias=True, exclude_none=True)
    order_obj["account"] = kid
    await state.add_order(order_id, order_obj)

    response.headers["Location"] = full_url_for(f"acme/order/{order_id}")
    await add_replay_nonce(response)
    return order


@app.post(
    "/acme/chall/{challenge_id}",
    response_model=Challenge,
    response_model_exclude_none=True,
)
async def respond_to_challenge(
    challenge_id: str,
    response: Response,
    background_tasks: BackgroundTasks,
    jws_data: dict[str, Any] = Depends(verify_jws),
) -> Challenge:
    kid = jws_data["kid"]
    account_data = await state.get_account_by_kid(kid)
    challenge_obj = await state.get_resource(challenge_id, "challenges")
    if not challenge_obj or not account_data or not is_owned_by(challenge_obj, kid):
        raise HTTPException(status_code=404, detail="Resource not found")

    # Find the corresponding authorization and order to pass IDs
    authz_id, order_id = await find_parent_ids_for_challenge(challenge_id, kid)

    if authz_id and order_id:
        authz_obj = await state.get_resource(authz_id, "authorizations")
        order_obj = await state.get_resource(order_id, "orders")
        if not authz_obj or not order_obj or not is_owned_by(authz_obj, kid) or not is_owned_by(order_obj, kid):
            raise HTTPException(status_code=404, detail="Resource not found")

        challenge_obj["status"] = "processing"
        await state.update_resource(challenge_id, "challenges", challenge_obj)
        background_tasks.add_task(
            verify_http01_challenge,
            challenge_id,
            authz_id,
            order_id,
            account_data["jwk"],
        )
    else:
        logger.error(f"Could not find parent authorization/order for challenge {challenge_id}")
        raise HTTPException(status_code=404, detail="Resource not found")

    # Add standard headers including nonce and ACME directory index link
    await add_replay_nonce(response)

    # Certbot requires an "up" Link header on challenge responses pointing to the parent authorization
    if authz_id:
        existing_link = response.headers.get("Link", "")
        up_link = f'<{full_url_for(f"acme/authz/{authz_id}")}>;rel="up"'
        response.headers["Link"] = f"{existing_link}, {up_link}" if existing_link else up_link
    return Challenge(**challenge_obj)


@app.post(
    "/acme/order/{order_id}/finalize",
    response_model=Order,
    response_model_exclude_none=True,
)
async def finalize_order(
    order_id: str,
    response: Response,
    background_tasks: BackgroundTasks,
    jws_data: dict[str, Any] = Depends(verify_jws),
) -> Order:
    payload = FinalizePayload(**jws_data["payload"])
    order_obj = await state.get_resource(order_id, "orders")
    kid = jws_data["kid"]

    account_jwk = jws_data["jwk"]
    if not account_jwk:
        raise HTTPException(status_code=500, detail="Could not retrieve account key")

    if not order_obj or not is_owned_by(order_obj, kid):
        raise HTTPException(status_code=404, detail="Order not found")
    if order_obj["status"] != "ready":
        raise HTTPException(
            status_code=403,
            detail=Problem(
                type="urn:ietf:params:acme:error:orderNotReady",
                detail=f"Order status is {order_obj['status']}, must be ready",
                status=403,
            ).model_dump(by_alias=True, exclude_none=True),
        )

    # Decode CSR from base64url with proper validation
    csr_der_b64 = payload.csr
    try:
        # Validate base64url encoding
        csr_der = base64.urlsafe_b64decode(csr_der_b64 + "=" * (-len(csr_der_b64) % 4))
        if not csr_der:
            raise ValueError("Empty CSR")
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=Problem(
                type="urn:ietf:params:acme:error:badCSR",
                detail=f"Invalid CSR encoding: {e}",
                status=400,
            ).model_dump(by_alias=True, exclude_none=True),
        )

    # Convert DER to PEM format for acme.sh with 64-character line wrapping
    def _wrap64(b: bytes) -> str:
        s = base64.b64encode(b).decode()
        return "\n".join(s[i : i + 64] for i in range(0, len(s), 64))

    csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + _wrap64(csr_der) + "\n-----END CERTIFICATE REQUEST-----"

    order_obj["status"] = "processing"
    order_obj.setdefault("expires", acme_timestamp_after(ORDER_EXPIRES_AFTER))
    await state.update_resource(order_id, "orders", order_obj)

    # Pass all required parameters including CSR validation data
    background_tasks.add_task(finalize_and_issue_cert, order_id, csr_pem, csr_der, account_jwk)

    await add_replay_nonce(response)
    return Order(**order_obj)


@app.post("/acme/cert/{cert_id}")
async def download_cert(cert_id: str, response: Response, jws_data: dict[str, Any] = Depends(verify_jws)) -> Response:
    cert_obj = await get_owned_certificate(cert_id, jws_data["kid"])
    if not cert_obj:
        raise HTTPException(status_code=404, detail="Certificate not found")

    cert_path = Path(cert_obj.get("path", Path(settings.CERT_STORAGE_PATH) / f"{cert_id}.pem"))
    if not cert_path.exists():
        raise HTTPException(status_code=404, detail="Certificate not found")

    with open(cert_path, "r", encoding="utf-8") as f:
        cert_content = f.read()

    # Build the response object first so we can attach headers (nonce, link)
    resp = Response(content=cert_content, media_type="application/pem-certificate-chain")
    await add_replay_nonce(resp)
    return resp


# --- POST-as-GET endpoints for polling resources ---


@app.post(
    "/acme/order/{order_id}",
    response_model=Order,
    response_model_exclude_none=True,
)
async def get_order(order_id: str, response: Response, jws_data: dict[str, Any] = Depends(verify_jws)) -> Order:
    # Check that payload is empty
    if jws_data["payload"]:
        raise HTTPException(400, "Payload must be empty for POST-as-GET")
    order_obj = await state.get_resource(order_id, "orders")
    if not order_obj or not is_owned_by(order_obj, jws_data["kid"]):
        raise HTTPException(404, "Order not found")
    await add_replay_nonce(response)
    return Order(**order_obj)


@app.post(
    "/acme/authz/{authz_id}",
    response_model=Authorization,
    response_model_exclude_none=True,
)
async def get_authorization(
    authz_id: str, response: Response, jws_data: dict[str, Any] = Depends(verify_jws)
) -> Authorization:
    if jws_data["payload"]:
        raise HTTPException(400, "Payload must be empty for POST-as-GET")
    authz_obj = await state.get_resource(authz_id, "authorizations")
    if not authz_obj or not is_owned_by(authz_obj, jws_data["kid"]):
        raise HTTPException(404, "Authorization not found")
    await add_replay_nonce(response)
    return Authorization(**authz_obj)


@app.get("/")
async def get_root(response: Response) -> Response:
    return RedirectResponse(url="https://github.com/cofob/acme-proxy-server")
