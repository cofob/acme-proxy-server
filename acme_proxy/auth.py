"""Authentication and JWS verification functions that depend on state."""

import base64
import json
from typing import Any

from fastapi import HTTPException, Request
from fastapi import status as http_status
from jose import exceptions, jws

from acme_proxy.config import settings
from acme_proxy.models import Problem
from acme_proxy.security import is_algorithm_allowed
from acme_proxy.state import state


async def verify_jws(request: Request) -> dict[str, Any]:
    """Verify JWS (JSON Web Signature) from ACME client request."""
    try:
        content_type = request.headers.get("content-type")
        if content_type != "application/jose+json":
            raise HTTPException(
                status_code=http_status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Invalid content type. Must be application/jose+json",
            )

        req_body = await request.json()
        protected_header_b64 = req_body["protected"]
        protected_header_str = base64.urlsafe_b64decode(
            protected_header_b64 + "=" * (-len(protected_header_b64) % 4)
        ).decode("utf-8")
        protected_header = json.loads(protected_header_str)

        # 1. Nonce Check
        nonce = protected_header.get("nonce")
        if not nonce or not await state.use_nonce(nonce):
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=Problem(
                    type="urn:ietf:params:acme:error:badNonce",
                    detail="Invalid anti-replay nonce.",
                    status=http_status.HTTP_400_BAD_REQUEST,
                ).model_dump(by_alias=True, exclude_none=True),
            )

        # 2. URL Check
        if protected_header.get("url") != str(request.url):
            raise HTTPException(
                status_code=http_status.HTTP_403_FORBIDDEN,
                detail=Problem(
                    type="urn:ietf:params:acme:error:unauthorized",
                    detail="JWS 'url' header does not match request URL.",
                    status=http_status.HTTP_403_FORBIDDEN,
                ).model_dump(by_alias=True, exclude_none=True),
            )

        # 3. Algorithm Validation
        algorithm = protected_header.get("alg")
        if not algorithm:
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=Problem(
                    type="urn:ietf:params:acme:error:badSignatureAlgorithm",
                    detail="Missing 'alg' field in JWS protected header.",
                    status=http_status.HTTP_400_BAD_REQUEST,
                ).model_dump(by_alias=True, exclude_none=True),
            )

        if not is_algorithm_allowed(algorithm, settings.ALLOWED_JWS_ALGORITHMS):
            problem = Problem(
                type="urn:ietf:params:acme:error:badSignatureAlgorithm",
                detail=f"Algorithm '{algorithm}' is not supported. Supported algorithms: {settings.ALLOWED_JWS_ALGORITHMS}",
                status=http_status.HTTP_400_BAD_REQUEST,
                algorithms=settings.ALLOWED_JWS_ALGORITHMS,
            )
            raise HTTPException(
                status_code=http_status.HTTP_400_BAD_REQUEST,
                detail=problem.model_dump(by_alias=True, exclude_none=True),
            )

        # 4. Signature Verification
        public_key_jwk = None
        if "jwk" in protected_header:  # For newAccount requests
            public_key_jwk = protected_header["jwk"]
        elif "kid" in protected_header:  # For existing accounts
            account_data = await state.get_account_by_kid(protected_header["kid"])
            if not account_data:
                raise HTTPException(
                    status_code=http_status.HTTP_401_UNAUTHORIZED,
                    detail=Problem(
                        type="urn:ietf:params:acme:error:accountDoesNotExist",
                        detail="Account not found for the given key ID.",
                        status=http_status.HTTP_401_UNAUTHORIZED,
                    ).model_dump(by_alias=True, exclude_none=True),
                )
            public_key_jwk = account_data["jwk"]
        else:
            raise ValueError("JWS must have 'jwk' or 'kid' in protected header")

        # Reconstruct the JWS compact serialization string for verification
        compact_jws = f"{req_body['protected']}.{req_body['payload']}.{req_body['signature']}"

        jws.verify(
            token=compact_jws,
            key=public_key_jwk,
            algorithms=[algorithm],  # Only allow the specific algorithm
        )

        payload_b64 = req_body["payload"]
        if not payload_b64:  # For POST-as-GET
            payload = {}
        else:
            payload_str = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)).decode("utf-8")
            payload = json.loads(payload_str)

        return {
            "payload": payload,
            "jwk": public_key_jwk,
            "kid": protected_header.get("kid"),
        }

    except (exceptions.JOSEError, ValueError, KeyError, json.JSONDecodeError) as e:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=Problem(
                type="urn:ietf:params:acme:error:malformed",
                detail=f"Failed to parse or verify JWS: {e}",
                status=http_status.HTTP_400_BAD_REQUEST,
            ).model_dump(by_alias=True, exclude_none=True),
        )
