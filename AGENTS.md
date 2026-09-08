# AGENTS.md

These shared instructions apply to every coding agent working in this repository.

## Working Agreement

- Preserve unrelated work in a dirty worktree. Do not reset, discard, or reformat files outside the requested change.
- Keep changes focused and verify them in proportion to their risk. For documentation-only changes, check links, commands, and referenced paths. For code or configuration changes, run the relevant project checks.
- Complete low-risk, documentation-only, and configuration-only changes in the parent session with proportional checks unless independent review is specifically warranted.
- Use a fresh, independent verifier and reviewer for high-risk changes affecting application behavior, persisted credentials, authentication, privacy, analytics, advertising, deployment, purchases, or external systems. They must not validate their own implementation.
- Only the orchestrating parent delegates workflow roles. Child implementers, verifiers, and reviewers return evidence to that parent without recursively spawning workflow agents. Use parallel agents only for genuinely independent work that materially improves speed or quality. Record any material limitation when a required check cannot run.
- Escalate ambiguity, risky Google/Firebase/Play Console changes, or an unavailable required model or tool instead of silently substituting a weaker workflow.

## Project Overview

kagienv is a Rust 2024 CLI for local encrypted secrets and child-process environment injection. Read `README.md` for user commands and `Cargo.toml` for dependencies. The vault uses age encryption and SQLite; macOS protects private keys with Keychain, while other platforms use password protection.

- `src/vault/` owns encryption, key handling, and storage.
- `src/commands/` owns add/list/delete/run/scan/install-hooks.
- Scanning compares actual secret values, rather than only credential-shaped patterns.
- Preserve owner-only storage permissions, encrypted values, key migration behavior, and the rule that listing never reveals values.
- Child command execution intentionally injects secrets. Do not print the resulting environment, credentials, or decrypted values in diagnostics.
- Use disposable test vaults and synthetic secrets. Do not exercise add/delete/migration against the user's real vault during routine tests.
- Hook installation changes Git/Claude configuration; test in a temporary repository and preserve existing hooks.
- `make install` replaces the installed binary; use it only when installation is requested.

## Verification and Agent Routing

Codex follows [docs/codex-workflow.md](docs/codex-workflow.md). For documentation/configuration changes, inspect references, syntax, and scoped diffs. For Rust changes:

```bash
cargo fmt --check
cargo check
cargo test
```

Review tests before execution for real-vault or Keychain side effects. Exercise affected commands with synthetic data in an isolated fixture; build success does not verify decryption, migration, permissions, secret redaction, child exit codes, or hook behavior. Encryption, persistence, and secret-handling changes require independent verification and review under the working agreement.
