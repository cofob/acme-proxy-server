import os
import stat

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # --- Server Configuration ---
    # The public-facing base URL of this ACME server.
    # Clients like certbot will use this to construct resource URLs.
    # Example: "http://localhost:8000" or "https://acme.local"
    SERVER_URL: str = "http://localhost:8000"

    # --- Domain Configuration ---
    # The base domain suffix this server is authorized to issue certificates for.
    # Example: "lo.f0rth.space"
    BASE_DOMAIN_SUFFIX: str = ""

    # --- State and Certificate Storage ---
    # Path to the JSON file for storing ACME server state.
    STATE_FILE_PATH: str = "acme_server_state.json"
    # Directory to store the final, issued certificates.
    CERT_STORAGE_PATH: str = "certs"

    # --- External ACME Client (acme.sh) Configuration ---
    # Path to the acme.sh script.
    ACME_SH_PATH: str = "/root/.acme.sh/acme.sh"
    # If staging is enabled, it will use the Let's Encrypt staging environment.
    # Set to True for testing, False for production.
    ACME_SH_STAGING: bool = False
    # The DNS API to use with acme.sh (e.g., 'dns_cf' for Cloudflare).
    ACME_SH_DNS_API: str = ""
    # The email for the Let's Encrypt account used by acme.sh
    ACME_SH_ACCOUNT_EMAIL: str = ""

    # --- DNS API Credentials ---
    # These must be set in your environment for acme.sh to work.
    # Example for Cloudflare:
    CF_KEY: str | None = None
    CF_EMAIL: str | None = None
    # Add other provider credentials as needed (e.g., AWS_ACCESS_KEY_ID).

    # --- Security Configuration ---
    # CIDR ranges allowed for HTTP-01 challenge validation (optional)
    # Example: "192.168.1.0/24,10.0.0.0/8" or leave empty to allow all
    ALLOWED_CHALLENGE_CIDR: str = ""

    # JWS algorithms allowed for request signatures
    ALLOWED_JWS_ALGORITHMS: list[str] = ["ES256", "EdDSA"]

    class Config:
        env_file = ".env"
        extra = "ignore"  # Ignore extra env vars not defined in the model


settings = Settings()

# Create storage directory with secure permissions if it doesn't exist
# Only owner can read/write/execute (700)
os.makedirs(settings.CERT_STORAGE_PATH, mode=stat.S_IRWXU, exist_ok=True)
