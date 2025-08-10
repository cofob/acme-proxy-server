import base64
import logging
import os
import socket
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union

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


# --- Helper Functions ---
def full_url_for(path: str) -> str:
    return f"{settings.SERVER_URL.rstrip('/')}/{path.lstrip('/')}"


# Public key equality helper (module-level with full typing for mypy)
PublicKeyTypes = Union[RSAPublicKey, EllipticCurvePublicKey]


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
    # ACME HTTP-01 challenge MUST be served on port 80 per RFC 8555
    url = f"http://{domain}:80/.well-known/acme-challenge/{token}"
    expected_content = get_key_authorization(token, account_jwk)

    try:
        # Security: Use strict HTTP client configuration
        timeout_config = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=10.0)

        async with httpx.AsyncClient(
            follow_redirects=False,  # RFC requirement: no redirects allowed
            timeout=timeout_config,
            limits=httpx.Limits(max_keepalive_connections=0),  # Disable connection reuse
        ) as client:
            # Resolve domain to IP for CIDR validation
            try:
                ip_address = socket.gethostbyname(domain)
                logger.info(f"Resolved {domain} to IP {ip_address}")

                # Validate IP against CIDR ranges if configured
                if settings.ALLOWED_CHALLENGE_CIDR:
                    if not validate_ip_in_cidr_ranges(ip_address, settings.ALLOWED_CHALLENGE_CIDR):
                        raise Exception(
                            f"Domain {domain} resolves to IP {ip_address} which is not in allowed CIDR ranges: {settings.ALLOWED_CHALLENGE_CIDR}"
                        )

            except socket.gaierror as e:
                raise Exception(f"Failed to resolve domain {domain}: {e}")

            # Perform the HTTP-01 challenge request
            response = await client.get(
                url,
                headers={
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
            raise Exception(
                f"HTTP-01 challenge content mismatch. Expected: {expected_content}, Got: {response_content}"
            )

        # Validate Content-Type if present (should be text/plain)
        content_type = response.headers.get("content-type", "").lower()
        if content_type and not content_type.startswith("text/plain"):
            logger.warning(f"Non-standard Content-Type for HTTP-01 response: {content_type}")

        logger.info(f"HTTP-01 validation successful for {domain}")
        challenge_obj["status"] = "valid"
        challenge_obj["validated"] = datetime.now(timezone.utc).isoformat()
        await state.update_resource(challenge_id, "challenges", challenge_obj)

        authz_obj["status"] = "valid"
        await state.update_resource(authz_id, "authorizations", authz_obj)

        # Check if all authorizations for the order are now valid
        all_valid = True
        for authz_url in order_obj["authorizations"]:
            authz_id_to_check = authz_url.split("/")[-1]
            authz_to_check = await state.get_resource(authz_id_to_check, "authorizations")
            if authz_to_check and authz_to_check.get("status") != "valid":
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
        error = Problem(type="urn:ietf:params:acme:error:unauthorized", detail=str(e), status=403)
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

        try:
            validate_csr(csr_der, order_identifiers, account_jwk)
            logger.info(f"CSR validation successful for order {order_id}")
        except ValueError as e:
            logger.error(f"CSR validation failed for order {order_id}: {e}")
            raise Exception(f"CSR validation failed: {e}")

        # Extract identifiers exactly as validated from the CSR
        identifiers_to_issue = [ident["value"] for ident in order_obj_dict["identifiers"]]

        # Use the provided CSR to ensure the certificate matches the client's key
        cert_content = await issue_certificate_with_acmesh(identifiers_to_issue, csr_pem=csr_pem)

        # Verify issued leaf certificate public key matches CSR public key
        csr_obj = x509.load_der_x509_csr(csr_der)
        csr_pub_any = csr_obj.public_key()

        # Parse first certificate in the returned fullchain as the leaf
        pem_certs: list[bytes] = []
        current: list[str] = []
        for line in cert_content.splitlines():
            current.append(line)
            if line.strip() == "-----END CERTIFICATE-----":
                pem_certs.append("\n".join(current).encode())
                current = []
        if not pem_certs:
            raise Exception("No PEM certificates found in returned fullchain content")

        leaf_cert = x509.load_pem_x509_certificate(pem_certs[0])
        leaf_pub_any = leaf_cert.public_key()

        # Narrow types for mypy and validate supported key types
        if not isinstance(csr_pub_any, (RSAPublicKey, EllipticCurvePublicKey)):
            raise Exception(f"Unsupported CSR public key type: {type(csr_pub_any)}")
        if not isinstance(leaf_pub_any, (RSAPublicKey, EllipticCurvePublicKey)):
            raise Exception(f"Unsupported certificate public key type: {type(leaf_pub_any)}")
        csr_pub: PublicKeyTypes = csr_pub_any
        leaf_pub: PublicKeyTypes = leaf_pub_any

        if not public_keys_equal(csr_pub, leaf_pub):
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
        order_obj_dict["certificate"] = full_url_for(f"acme/cert/{cert_id}")
        await state.update_resource(order_id, "orders", order_obj_dict)
        logger.info(f"Certificate for order {order_id} issued and stored at {cert_path}")

    except Exception as e:
        logger.error(f"Finalization failed for order {order_id}: {e}")
        order_obj_dict["status"] = "invalid"
        error = Problem(type="urn:ietf:params:acme:error:serverInternal", detail=str(e), status=500)
        order_obj_dict["error"] = error.model_dump(by_alias=True, exclude_none=True)
        await state.update_resource(order_id, "orders", order_obj_dict)


# --- ACME Endpoints ---


@app.get("/directory", response_model=Directory)
async def get_directory(response: Response) -> Directory:
    await add_replay_nonce(response)
    dir_obj = Directory(
        new_nonce=full_url_for("acme/new-nonce"),
        new_account=full_url_for("acme/new-account"),
        new_order=full_url_for("acme/new-order"),
        revoke_cert=full_url_for("acme/revoke-cert"),
        key_change=full_url_for("acme/key-change"),
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
        if not ident.value.endswith(f".{settings.BASE_DOMAIN_SUFFIX}"):
            raise HTTPException(
                status_code=403,
                detail=Problem(
                    type="urn:ietf:params:acme:error:rejectedIdentifier",
                    detail=f"Identifier {ident.value} is not allowed.",
                    status=403,
                ).model_dump(by_alias=True, exclude_none=True),
            )

    order_id = str(uuid.uuid4())
    auth_urls = []

    for ident in payload.identifiers:
        authz_id = str(uuid.uuid4())
        challenge_id = str(uuid.uuid4())

        challenge = Challenge(
            type="http-01",
            url=full_url_for(f"acme/chall/{challenge_id}"),
            token=generate_token(),
        )
        auth = Authorization(identifier=ident, challenges=[challenge])

        await state.add_challenge(challenge_id, challenge.model_dump(by_alias=True, exclude_none=True))
        await state.add_authorization(authz_id, auth.model_dump(by_alias=True, exclude_none=True))
        auth_urls.append(full_url_for(f"acme/authz/{authz_id}"))

    order = Order(
        identifiers=payload.identifiers,
        notBefore=payload.not_before,
        notAfter=payload.not_after,
        authorizations=auth_urls,
        finalize=full_url_for(f"acme/order/{order_id}/finalize"),
    )

    await state.add_order(order_id, order.model_dump(by_alias=True, exclude_none=True))

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
    if not challenge_obj or not account_data:
        raise HTTPException(status_code=404, detail="Resource not found")

    challenge_obj["status"] = "processing"
    await state.update_resource(challenge_id, "challenges", challenge_obj)

    # Find the corresponding authorization and order to pass IDs
    authz_id, order_id = None, None
    for oid, o in (await state.get_resource(None, "orders")).items():
        for auth_url in o["authorizations"]:
            aid = auth_url.split("/")[-1]
            auth = await state.get_resource(aid, "authorizations")
            if any(c["url"].endswith(challenge_id) for c in auth["challenges"]):
                authz_id, order_id = aid, oid
                break
        if authz_id:
            break

    if authz_id and order_id:
        background_tasks.add_task(
            verify_http01_challenge,
            challenge_id,
            authz_id,
            order_id,
            account_data["jwk"],
        )
    else:
        logger.error(f"Could not find parent authorization/order for challenge {challenge_id}")

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

    # Get account JWK (could be from jwk field for new accounts or kid for existing)
    account_jwk = jws_data["jwk"]
    if not account_jwk and "kid" in jws_data:
        account_data = await state.get_account_by_kid(jws_data["kid"])
        if account_data:
            account_jwk = account_data["jwk"]

    if not account_jwk:
        raise HTTPException(status_code=500, detail="Could not retrieve account key")

    if not order_obj:
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
    await state.update_resource(order_id, "orders", order_obj)

    # Pass all required parameters including CSR validation data
    background_tasks.add_task(finalize_and_issue_cert, order_id, csr_pem, csr_der, account_jwk)

    await add_replay_nonce(response)
    return Order(**order_obj)


@app.post("/acme/cert/{cert_id}")
async def download_cert(cert_id: str, response: Response, jws_data: dict[str, Any] = Depends(verify_jws)) -> Response:
    cert_path = Path(settings.CERT_STORAGE_PATH) / f"{cert_id}.pem"
    if not cert_path.exists():
        raise HTTPException(status_code=404, detail="Certificate not found")

    with open(cert_path, "r") as f:
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
    if not order_obj:
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
    if not authz_obj:
        raise HTTPException(404, "Authorization not found")
    await add_replay_nonce(response)
    return Authorization(**authz_obj)


@app.get("/")
async def get_root(response: Response) -> Response:
    return RedirectResponse(url="https://github.com/cofob/acme-proxy-server")
