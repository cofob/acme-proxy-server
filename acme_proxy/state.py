import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from acme_proxy.config import settings
from acme_proxy.security import calculate_jwk_thumbprint

logger = logging.getLogger(__name__)


class StateManager:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self._lock = asyncio.Lock()
        self.data: dict[str, Any] = {
            "accounts": {},  # {kid: {"jwk": ..., "obj": account_obj}}
            "orders": {},  # {order_id: order_obj}
            "authorizations": {},  # {authz_id: authz_obj}
            "challenges": {},  # {challenge_id: challenge_obj}
            "nonces": {},  # {nonce: expiry_timestamp}
        }
        self.load()

    def load(self) -> None:
        if self.file_path.exists():
            try:
                with open(self.file_path, "r") as f:
                    loaded_data = json.load(f)

                    # Handle nonce format migration: list/set -> dict with timestamps
                    nonces = loaded_data.get("nonces", {})
                    if isinstance(nonces, (list, set)):
                        # Convert old format to new format (all nonces expire in 5 minutes)
                        expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
                        loaded_data["nonces"] = {nonce: expiry for nonce in nonces}
                    elif isinstance(nonces, dict):
                        # Clean expired nonces on load
                        loaded_data["nonces"] = self._clean_expired_nonces(nonces)

                    self.data = loaded_data
                    logger.info(f"State loaded from {self.file_path}")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Could not load state file: {e}. Starting fresh.")

    async def save(self) -> None:
        async with self._lock:
            temp_path = self.file_path.with_suffix(".tmp")
            try:
                # Clean expired nonces before saving
                self.data["nonces"] = self._clean_expired_nonces(self.data["nonces"])

                with open(temp_path, "w") as f:
                    json.dump(self.data, f, indent=2)
                temp_path.rename(self.file_path)  # Atomic operation
                logger.debug("State saved successfully.")
            except IOError as e:
                logger.error(f"Could not save state to {self.file_path}: {e}")

    def _clean_expired_nonces(self, nonces: dict[str, str]) -> dict[str, str]:
        """Remove expired nonces from the dictionary."""
        now = datetime.now(timezone.utc)
        cleaned = {}
        expired_count = 0

        for nonce, expiry_str in nonces.items():
            try:
                expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                if expiry > now:
                    cleaned[nonce] = expiry_str
                else:
                    expired_count += 1
            except (ValueError, AttributeError):
                # Invalid timestamp format, consider expired
                expired_count += 1

        if expired_count > 0:
            logger.debug(f"Cleaned {expired_count} expired nonces")

        return cleaned

    async def add_nonce(self, nonce: str) -> None:
        """Add a nonce with 5-minute expiration time."""
        async with self._lock:
            expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            self.data["nonces"][nonce] = expiry

            # Periodically clean expired nonces to prevent memory growth
            if len(self.data["nonces"]) % 100 == 0:  # Clean every 100 nonces
                self.data["nonces"] = self._clean_expired_nonces(self.data["nonces"])

    async def use_nonce(self, nonce: str) -> bool:
        """Use a nonce if it exists and hasn't expired."""
        async with self._lock:
            if nonce not in self.data["nonces"]:
                return False

            # Check if nonce has expired
            expiry_str = self.data["nonces"][nonce]
            try:
                expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                if expiry <= datetime.now(timezone.utc):
                    # Nonce has expired, remove it
                    del self.data["nonces"][nonce]
                    logger.debug(f"Nonce {nonce[:8]}... has expired")
                    return False
            except (ValueError, AttributeError):
                # Invalid timestamp, consider expired
                del self.data["nonces"][nonce]
                return False

            # Nonce is valid and not expired, consume it
            del self.data["nonces"][nonce]
            return True

    async def get_account_by_key(self, public_jwk: dict[str, Any]) -> Any | None:
        async with self._lock:
            key_thumbprint = calculate_jwk_thumbprint(public_jwk)
            for acc in self.data["accounts"].values():
                # Check if the thumbprint matches the one stored with the account
                if acc.get("thumbprint") == key_thumbprint:
                    return acc["obj"]
            return None

    async def get_account_by_kid(self, kid: str) -> Any | None:
        async with self._lock:
            return self.data["accounts"].get(kid)

    async def add_account(self, kid: str, public_jwk: dict[str, Any], account_obj: dict[str, Any]) -> None:
        async with self._lock:
            # Calculate and store the thumbprint when the account is created
            thumbprint = calculate_jwk_thumbprint(public_jwk)
            self.data["accounts"][kid] = {"jwk": public_jwk, "obj": account_obj, "thumbprint": thumbprint}
        await self.save()

    async def add_order(self, order_id: str, order_obj: dict[str, Any]) -> None:
        async with self._lock:
            self.data["orders"][order_id] = order_obj
        await self.save()

    async def add_authorization(self, auth_id: str, auth_obj: dict[str, Any]) -> None:
        async with self._lock:
            self.data["authorizations"][auth_id] = auth_obj
        await self.save()

    async def add_challenge(self, challenge_id: str, challenge_obj: dict[str, Any]) -> None:
        async with self._lock:
            self.data["challenges"][challenge_id] = challenge_obj
        await self.save()

    # Generic getters and updaters to handle objects by reference
    async def get_resource(self, resource_id: str | None, resource_type: str) -> Any:
        """
        Gets a specific resource by ID, or the entire resource collection if ID is None.
        """
        async with self._lock:
            if resource_id is None:
                # Return the entire dictionary for the resource type, or an empty one.
                return self.data.get(resource_type, {})
            # Return a specific resource by its ID.
            return self.data.get(resource_type, {}).get(resource_id)

    async def update_resource(self, resource_id: str, resource_type: str, new_obj: dict[str, Any]) -> None:
        async with self._lock:
            if resource_id in self.data[resource_type]:
                self.data[resource_type][resource_id] = new_obj
            else:
                raise KeyError(f"Resource {resource_id} not found in {resource_type}")
        await self.save()


state = StateManager(settings.STATE_FILE_PATH)
