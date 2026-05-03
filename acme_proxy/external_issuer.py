import asyncio
import logging
import os
import re
import shlex
import stat
import sys
from pathlib import Path

from acme_proxy.config import settings
from acme_proxy.security import AcmeProblemError

logger = logging.getLogger(__name__)

# A lock to prevent multiple acme.sh instances from running simultaneously
# as it can corrupt its internal state.
ACME_SH_LOCK = asyncio.Lock()


def _write_openssl_csr_filter_wrapper(wrapper_path: Path) -> None:
    """Write an openssl shim that hides duplicate CN/SAN DNS entries from acme.sh CSR parsing."""
    wrapper_source = f"""#!{sys.executable}
import os
import re
import subprocess
import sys


def arg_after(args, option):
    try:
        index = args.index(option)
    except ValueError:
        return None
    next_index = index + 1
    if next_index >= len(args):
        return None
    return args[next_index]


def should_filter(args):
    return args[:1] == ["req"] and "-noout" in args and "-text" in args


def common_name(real_openssl, csr_path):
    proc = subprocess.run(
        [real_openssl, "req", "-noout", "-in", csr_path, "-subject"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    match = re.search(r"CN\\s*=\\s*([^,/]+)", proc.stdout)
    if not match:
        return None
    return match.group(1).strip()


def filter_duplicate_san(text, cn):
    target = f"DNS:{{cn}}"
    filtered_lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("DNS:"):
            indent = line[: len(line) - len(stripped)]
            entries = [entry.strip() for entry in stripped.split(",")]
            entries = [entry for entry in entries if entry != target]
            if not entries:
                continue
            line = indent + ", ".join(entries)
        filtered_lines.append(line)
    newline = "\\n" if text.endswith("\\n") else ""
    return "\\n".join(filtered_lines) + newline


def main():
    real_openssl = os.environ.get("ACME_PROXY_REAL_OPENSSL", "openssl")
    args = sys.argv[1:]
    csr_path = os.environ.get("ACME_PROXY_SIGNCSR_PATH")
    input_path = arg_after(args, "-in")

    if should_filter(args) and input_path and (not csr_path or input_path == csr_path):
        proc = subprocess.run(
            [real_openssl, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            sys.stdout.write(proc.stdout)
            return proc.returncode
        cn = common_name(real_openssl, input_path)
        if cn:
            sys.stdout.write(filter_duplicate_san(proc.stdout, cn))
        else:
            sys.stdout.write(proc.stdout)
        return 0

    os.execvp(real_openssl, [real_openssl, *args])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
"""
    wrapper_path.write_text(wrapper_source, encoding="utf-8")
    os.chmod(wrapper_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


async def issue_certificate_with_acmesh(identifiers: list[str], csr_pem: str | None = None) -> str:
    """
    Calls acme.sh to issue a certificate for the given identifiers.

    Args:
        identifiers: A list of domain names.
        csr_pem: Optional PEM-encoded CSR content. When provided, acme.sh will
            use this CSR and will not generate or manage a private key. The
            resulting certificate will match the CSR's public key.

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
    cert_output_path = output_dir / f"{main_domain}.cert.pem"
    chain_output_path = output_dir / f"{main_domain}.fullchain.pem"
    csr_path: Path | None = None
    openssl_wrapper_path: Path | None = None

    async with ACME_SH_LOCK:
        logger.info(f"Issuing new certificate for: {identifiers}")

        # Require DNS API to be configured (we use DNS-01 to avoid HTTP serving)
        if not settings.ACME_SH_DNS_API:
            raise Exception(
                "ACME_SH_DNS_API is not configured. Set a DNS provider (e.g., 'dns_cf') in settings or environment."
            )

        # Prepare command and environment
        command = [settings.ACME_SH_PATH]
        # Use --signcsr when a CSR is provided, otherwise do a normal --issue
        command.append("--signcsr" if csr_pem else "--issue")
        command.extend(["--force", "--accountemail", settings.ACME_SH_ACCOUNT_EMAIL, "--log"])

        # If CSR is provided, write it securely and instruct acme.sh to use it.
        # In CSR mode, acme.sh derives identifiers from the CSR and does not
        # generate or save a private key.
        if csr_pem:
            # Securely create CSR file with owner read/write only
            csr_path = output_dir / f"{main_domain}.csr.pem"
            fd = os.open(csr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(csr_pem)
            except Exception:
                os.close(fd)
                raise
            command.extend(
                [
                    "--csr",
                    str(csr_path),
                    "--cert-file",
                    str(cert_output_path),
                    "--fullchain-file",
                    str(chain_output_path),
                ]
            )
            # Append any additional user-specified flags for the --issue flow
            if settings.ACME_SH_ADDITIONAL.strip():
                try:
                    additional_args = shlex.split(settings.ACME_SH_ADDITIONAL)
                    command.extend(additional_args)
                except ValueError:
                    # If parsing fails, ignore additional flags to avoid breaking issuance
                    pass
        else:
            # No CSR provided: acme.sh will generate a new keypair and CSR.
            command.extend(
                [
                    "--key-file",
                    str(key_output_path),
                    "--cert-file",
                    str(cert_output_path),
                    "--fullchain-file",
                    str(chain_output_path),
                ]
            )
            # Append any additional user-specified flags for the --issue flow
            if settings.ACME_SH_ADDITIONAL.strip():
                try:
                    additional_args = shlex.split(settings.ACME_SH_ADDITIONAL)
                    command.extend(additional_args)
                except ValueError:
                    # If parsing fails, ignore additional flags to avoid breaking issuance
                    pass
        if settings.ACME_SH_STAGING:
            command.append("--staging")
        # Pass identifiers only in normal issue mode; for --signcsr acme.sh derives them from the CSR
        if not csr_pem:
            for identifier in identifiers:
                command.extend(["-d", identifier])
        # Use DNS-01 with configured provider
        command.extend(["--dns", settings.ACME_SH_DNS_API])

        # Prepare environment variables for acme.sh DNS plugin
        env = os.environ.copy()
        if settings.CF_KEY:
            env["CF_KEY"] = settings.CF_KEY
        if settings.CF_EMAIL:
            env["CF_EMAIL"] = settings.CF_EMAIL
        if csr_path is not None:
            real_openssl = env.get("ACME_OPENSSL_BIN", "openssl")
            openssl_wrapper_path = output_dir / ".acme-proxy-openssl-filter.py"
            _write_openssl_csr_filter_wrapper(openssl_wrapper_path)
            env["ACME_PROXY_REAL_OPENSSL"] = real_openssl
            env["ACME_PROXY_SIGNCSR_PATH"] = str(csr_path)
            env["ACME_OPENSSL_BIN"] = str(openssl_wrapper_path)
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
            out = stdout.decode()
            err = stderr.decode()
            logger.error(f"STDOUT: {out}")
            logger.error(f"STDERR: {err}")
            # Map common duplicate identifier error to ACME problem
            if "duplicated" in err.lower() or "duplicated" in out.lower():
                raise AcmeProblemError(
                    problem_type="urn:ietf:params:acme:error:rejectedIdentifier",
                    detail="One or more identifiers are duplicated",
                    status=400,
                )
            raise Exception(f"acme.sh execution failed: {err}")

        logger.info(f"acme.sh successfully issued certificate for {main_domain}.")
        logger.debug(f"STDOUT: {stdout.decode()}")

    if not chain_output_path.exists():
        raise FileNotFoundError(f"Certificate chain not found at {chain_output_path}")
    if not cert_output_path.exists():
        raise FileNotFoundError(f"Leaf certificate not found at {cert_output_path}")

    # Ensure certificate files have secure permissions (owner read/write only)
    if key_output_path.exists():
        os.chmod(key_output_path, stat.S_IRUSR | stat.S_IWUSR)
    if chain_output_path.exists():
        os.chmod(chain_output_path, stat.S_IRUSR | stat.S_IWUSR)
    if cert_output_path.exists():
        os.chmod(cert_output_path, stat.S_IRUSR | stat.S_IWUSR)

    # Best-effort cleanup of temporary files we created
    for temporary_path in (csr_path, openssl_wrapper_path):
        if temporary_path and temporary_path.exists():
            try:
                os.remove(temporary_path)
            except OSError:
                pass

    # Ensure the returned content starts with the exact leaf certificate, without duplicates
    cert_content = cert_output_path.read_text(encoding="utf-8").strip()
    chain_content = chain_output_path.read_text(encoding="utf-8").strip()

    def split_pem_blocks(pem_text: str) -> list[str]:
        blocks: list[str] = []
        current: list[str] = []
        for line in pem_text.splitlines():
            current.append(line)
            if line.strip() == "-----END CERTIFICATE-----":
                block = "\n".join(current).strip()
                blocks.append(block)
                current = []
        if current:
            # Incomplete block; ignore
            pass
        return blocks

    leaf_block = cert_content
    chain_blocks = split_pem_blocks(chain_content)

    # Remove any existing occurrence of the leaf from the chain blocks
    chain_blocks = [b for b in chain_blocks if b != leaf_block]

    combined_blocks = [leaf_block] + chain_blocks
    combined = "\n".join(combined_blocks) + "\n"

    # Update the fullchain file on disk to the combined content for consistency
    try:
        with open(chain_output_path, "w", encoding="utf-8") as f:
            f.write(combined)
    except Exception:
        # Non-fatal; still return combined
        pass
    return combined
