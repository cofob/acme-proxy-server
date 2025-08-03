# ACME Proxy Server

A Python-based ACME (Automatic Certificate Management Environment) proxy server that simplifies SSL certificate management for local networks. This project was developed for the f0rth.space hackerspace to streamline the management of SSL certificates for local network services.

## Overview

The ACME Proxy Server implements the ACME protocol (RFC 8555) and acts as a proxy between ACME clients (like certbot) and external certificate authorities. It handles HTTP-01 challenge validation locally while delegating the actual certificate issuance to acme.sh, which communicates with Let's Encrypt or other ACME-compatible CAs.

## Features

### Core ACME Protocol Support
- **Complete ACME Implementation**: Full RFC 8555 compliant ACME server with directory, account management, order processing, and certificate issuance
- **HTTP-01 Challenge Validation**: Automatic validation of domain ownership through HTTP-01 challenges with configurable CIDR restrictions
- **Account Management**: Support for account creation, key rollover, and deactivation
- **JWS Authentication**: Request authentication using JSON Web Signature with ES256 and EdDSA algorithms

### Certificate Management
- **External Certificate Issuance**: Integrates with acme.sh to issue certificates from Let's Encrypt or other ACME providers
- **Wildcard Certificate Support**: Automatic issuance of both domain and wildcard certificates (*.domain)
- **Certificate Storage**: Organized certificate storage with automatic directory management
- **DNS Provider Integration**: Support for various DNS providers through acme.sh (Cloudflare, AWS Route53, etc.)

### Security Features
- **CIDR-based Access Control**: Restrict HTTP-01 challenge validation to specific IP ranges
- **Request Authentication**: All requests authenticated via JWS with anti-replay protection
- **CSR Validation**: Comprehensive Certificate Signing Request validation
- **Domain Restriction**: Configurable base domain suffix to limit certificate issuance scope

### Operational Features
- **Domain Scoping**: Restrict certificate issuance to specific domain suffixes
- **Staging Environment Support**: Test against Let's Encrypt staging environment
- **Comprehensive Logging**: Detailed logging for monitoring and debugging
- **State Persistence**: JSON-based state storage for server resilience
- **Background Processing**: Asynchronous challenge validation and certificate issuance

## Configuration

The server is configured through environment variables or a `.env` file:

### Core Settings
```env
# Server Configuration
SERVER_URL=http://localhost:8000          # Public-facing server URL
BASE_DOMAIN_SUFFIX=lo.f0rth.space         # Allowed domain suffix for certificates

# Storage
STATE_FILE_PATH=acme_server_state.json    # ACME state storage
CERT_STORAGE_PATH=certs                   # Certificate storage directory
```

### ACME.sh Integration
```env
# ACME.sh Configuration
ACME_SH_PATH=/root/.acme.sh/acme.sh       # Path to acme.sh script
ACME_SH_STAGING=false                     # Use Let's Encrypt staging (true/false)
ACME_SH_DNS_API=dns_cf                    # DNS provider API (e.g., dns_cf for Cloudflare)
ACME_SH_ACCOUNT_EMAIL=admin@example.com   # Email for Let's Encrypt account
```

### DNS Provider Credentials
```env
# Cloudflare (example)
CF_Token=your_cloudflare_token
CF_Account_ID=your_cloudflare_account_id
```

### Security Settings
```env
# Security Configuration
ALLOWED_CHALLENGE_CIDR=192.168.1.0/24,10.0.0.0/8  # CIDR ranges for HTTP-01 validation
ALLOWED_JWS_ALGORITHMS=["ES256", "EdDSA"]           # Allowed JWS signature algorithms
```

## Deployment

### Docker Container

The ACME Proxy Server is available as a Docker container at `ghcr.io/cofob/acme-proxy-server`.

#### Quick Start
```bash
# Pull the image
docker pull ghcr.io/cofob/acme-proxy-server:latest

# Run with basic configuration
docker run -d \
  --name acme-proxy \
  -p 8000:8000 \
  -v $(pwd)/certs:/certs \
  -v $(pwd)/state:/state \
  -e SERVER_URL=https://acme.lo.f0rth.space \
  -e BASE_DOMAIN_SUFFIX=lo.f0rth.space \
  -e ACME_SH_DNS_API=dns_cf \
  -e ACME_SH_ACCOUNT_EMAIL=admin@f0rth.space \
  ghcr.io/cofob/acme-proxy-server:latest
```

#### Docker Compose
```yaml
version: '3.8'
services:
  acme-proxy:
    image: ghcr.io/cofob/acme-proxy-server:latest
    ports:
      - "8000:8000"
    volumes:
      - ./certs:/app/certs
      - ./state:/app/state
    environment:
      - SERVER_URL=https://acme.lo.f0rth.space
      - BASE_DOMAIN_SUFFIX=lo.f0rth.space
      - ACME_SH_DNS_API=dns_cf
      - ACME_SH_ACCOUNT_EMAIL=admin@f0rth.space
      - ALLOWED_CHALLENGE_CIDR=192.168.0.0/16,10.0.0.0/8
    restart: unless-stopped
```

### Local Development
```bash
# Install dependencies
uv sync

# Run the server
uv run uvicorn acme_proxy.main:app --host 0.0.0.0 --port 8000 --reload
```

## Usage

### ACME Client Configuration

Configure your ACME client to use the proxy server:

#### Certbot
```bash
certbot certonly \
  --server https://acme.lo.f0rth.space/directory \
  --preferred-challenges http \
  -d your-domain.lo.f0rth.space
```

#### acme.sh Client
```bash
acme.sh --issue \
  --server https://acme.lo.f0rth.space/directory \
  --domain butler.lo.f0rth.space \
  --webroot /var/www/html
```

### API Endpoints

The server provides standard ACME endpoints:
- `GET /directory` - ACME directory
- `GET|HEAD /acme/new-nonce` - Get fresh nonce
- `POST /acme/new-account` - Create account
- `POST /acme/new-order` - Submit certificate order
- `POST /acme/chall/{id}` - Respond to challenge
- `POST /acme/order/{id}/finalize` - Finalize order

## Architecture

The ACME Proxy Server consists of several key components:

- **Main Application** (`main.py`): FastAPI-based ACME server implementation
- **Authentication** (`auth.py`): JWS verification and request authentication
- **External Issuer** (`external_issuer.py`): Integration with acme.sh for certificate issuance
- **Security** (`security.py`): Cryptographic utilities and validation
- **State Management** (`state.py`): Persistent storage for ACME resources
- **Configuration** (`config.py`): Environment-based configuration management

## Development

This project was specifically developed for the f0rth.space hackerspace to address the complexity of managing SSL certificates for various local network services. It provides a centralized, automated solution for certificate provisioning while maintaining security and compliance with ACME standards.

### Requirements
- Python 3.13+
- acme.sh (for certificate issuance)
- DNS provider API access (for DNS-01 challenges)

### Building
```bash
# Build Docker image
docker build -t acme-proxy-server .

# Lint code
uv run ruff check
uv run mypy .
```

## License

This project is licensed under the terms specified in the LICENSE file.
