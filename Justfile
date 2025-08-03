# Show this message
default:
    @just --list

# Sync uv
sync:
    uv sync --all-groups --all-packages

# Autoformat code
fmt:
    nixfmt flake.nix
    ruff format .
    ruff check --select I --fix .  # isort

# Run lints and tests
check:
    mypy --install-types --non-interactive .
    ruff check .
    ruff format --check .

# Fix linting issues
fix:
    ruff check --fix .
    ruff format .

# Run CI checks
ci:
    just check
