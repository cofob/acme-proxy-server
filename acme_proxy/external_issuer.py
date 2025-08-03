import asyncio
import logging
import os
import re
import stat
from pathlib import Path
from typing import List

from acme_proxy.config import settings

logger = logging.getLogger(__name__)

# A lock to prevent multiple acme.sh instances from running simultaneously
# as it can corrupt its internal state.
ACME_SH_LOCK = asyncio.Lock()


async def issue_certificate_with_acmesh(identifiers: List[str]) -> str:
    """
    Calls acme.sh to issue a certificate for the given identifiers.

    Args:
        identifiers: A list of domain names.

    Returns:
        The content of the full certificate chain (fullchain.cer).

    Raises:
        Exception: If acme.sh fails.
    """
    if not identifiers:
        raise ValueError("No identifiers provided for certificate issuance.")

    # Validate identifiers to prevent command injection
    for identifier in identifiers:
        if not re.fullmatch(r"([a-zA-Z0-9\-\*]+\.)+[a-zA-Z]{2,}", identifier):
            raise ValueError(f"Invalid identifier format: {identifier}")

    main_domain = identifiers[0]
    output_dir = Path(settings.CERT_STORAGE_PATH)
    key_output_path = output_dir / f"{main_domain}.key.pem"
    chain_output_path = output_dir / f"{main_domain}.chain.pem"

    async with ACME_SH_LOCK:
        logger.info(f"Issuing new certificate for: {identifiers}")

        # Prepare command and environment
        command = [
            settings.ACME_SH_PATH,
            "--issue",
            "--force",
            "--dns",
            settings.ACME_SH_DNS_API,
            "--accountemail",
            settings.ACME_SH_ACCOUNT_EMAIL,
            "--log",
            "--key-file",
            str(key_output_path),
            "--fullchain-file",
            str(chain_output_path),
        ]
        if settings.ACME_SH_STAGING:
            command.append("--staging")
        for identifier in identifiers:
            command.extend(["-d", identifier])

        # Prepare environment variables for acme.sh DNS plugin
        env = os.environ.copy()
        if settings.CF_KEY:
            env["CF_KEY"] = settings.CF_KEY
        if settings.CF_EMAIL:
            env["CF_EMAIL"] = settings.CF_EMAIL
        # Add other DNS providers' env vars here

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.error(f"acme.sh failed for {main_domain}.")
            logger.error(f"STDOUT: {stdout.decode()}")
            logger.error(f"STDERR: {stderr.decode()}")
            raise Exception(f"acme.sh execution failed: {stderr.decode()}")

        logger.info(f"acme.sh successfully issued certificate for {main_domain}.")
        logger.debug(f"STDOUT: {stdout.decode()}")

    if not chain_output_path.exists():
        raise FileNotFoundError(f"Certificate chain not found at {chain_output_path}")

    # Ensure certificate files have secure permissions (owner read/write only)
    if key_output_path.exists():
        os.chmod(key_output_path, stat.S_IRUSR | stat.S_IWUSR)
    if chain_output_path.exists():
        os.chmod(chain_output_path, stat.S_IRUSR | stat.S_IWUSR)

    return chain_output_path.read_text(encoding="utf-8")
