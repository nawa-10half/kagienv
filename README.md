# shush

> "shh, don't leak my secrets."

A local-first secret manager for developers. Built for the VibeCoding era where AI agents can accidentally push your API keys.

## The Problem

- `.env` files with API keys get accidentally committed
- AI coding agents (`git add .` → `git push`) don't know what's sensitive
- Cloud-based secret managers require trusting a third party with your keys
- `~/.aws/credentials` sits in plaintext on disk, readable by any process

## The Solution

**shush** keeps your real secrets in an encrypted local vault (`~/.shush/`), outside your project directory. Secrets are injected as environment variables only when you need them.

```bash
# Add secrets to your local vault
shush add OPENAI_API_KEY sk-abc123...
shush add AWS_ACCESS_KEY_ID AKIA...
shush add AWS_SECRET_ACCESS_KEY wJalr...

# Run any command with secrets injected as env vars
shush run npm start
shush run aws s3 ls

# Scan for hardcoded secrets in your codebase
shush scan

# Install git pre-push hook to block pushes containing secrets
shush install-hooks
```

## Quick Start

### Install

```bash
cargo install --path .
```

### Usage

```bash
# Store a secret
shush add <NAME> <VALUE>

# List stored secrets (values are never shown)
shush list

# Delete a secret
shush delete <NAME>

# Run a command with all secrets injected as environment variables
shush run <command...>

# Scan current directory for hardcoded secret values
shush scan

# Install git pre-push hook + Claude Code hooks
shush install-hooks
```

### Replace ~/.aws/credentials

AWS CLI prioritizes environment variables over `~/.aws/credentials`:

```bash
shush add AWS_ACCESS_KEY_ID "your-access-key"
shush add AWS_SECRET_ACCESS_KEY "your-secret-key"

# Now use shush instead of credentials file
shush run aws s3 ls
shush run aws sts get-caller-identity
```

**Note:** Environment variable names must be **UPPERCASE** (e.g. `AWS_ACCESS_KEY_ID`, not `aws_access_key_id`).

## How It Works

- **Encryption:** Each secret value is encrypted with [age](https://github.com/FiloSottile/age) (x25519) before storage
- **Storage:** Encrypted values stored in SQLite (`~/.shush/vault.db`)
- **Keys:** An age keypair is generated on first use at `~/.shush/keys/identity.txt`
- **Permissions:** Vault directory (700) and key file (600) are restricted to owner only
- **Scan:** Compares actual vault values against your codebase — not pattern matching

```
~/.shush/              (700)
├── keys/
│   └── identity.txt   (600) age x25519 private key
└── vault.db           SQLite with encrypted secret values
```

## Scan & Git Hooks

`shush scan` detects hardcoded secrets by matching **actual vault values** against files in your codebase. This catches secrets that pattern-based scanners miss — like when an AI agent writes your API key directly into source code.

```bash
shush install-hooks
```

This installs:
- **Git pre-push hook** — runs `shush scan` before every push, blocks if secrets are found
- **Claude Code hooks** — runs `shush scan` before tool execution

## Status

MVP (v0.1) — core functionality is implemented and usable.

### Implemented
- Encrypted vault with age + SQLite
- `add`, `list`, `delete`, `run`, `scan`, `install-hooks` commands
- Git pre-push hook and Claude Code hook integration

### Planned
- Team sharing via public-key encryption (`shush share / receive`)
- macOS Keychain / Touch ID integration
- `.env` file import (`shush import .env`)
- SQLCipher for database-level encryption

## License

MIT
