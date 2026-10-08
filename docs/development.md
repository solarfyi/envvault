# Development

## Prerequisites

- Rust stable (1.85+, edition 2024)
- A C toolchain for the bundled SQLite (`rusqlite`): MSVC Build Tools on
  Windows, `cc` + `make` on Linux
- Node.js ≥ 20 (only for the desktop UI, when working on it)

## Build & test

```bash
cargo build            # debug build
cargo test             # unit + integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release  # optimized binary in target/release/envvault
```

Run the CLI without installing:

```bash
cargo run -- init
cargo run -- project create my-api
```

## Local development vault

Point EnvVault at throwaway paths so you never touch your real vault:

```powershell
# PowerShell
$env:ENVVAULT_VAULT      = "$env:TEMP\ev-dev\vault.db"
$env:ENVVAULT_CONFIG_DIR = "$env:TEMP\ev-dev\cfg"
$env:ENVVAULT_PASSWORD   = "dev-only-password"   # optional, skips prompts
```

```bash
# bash
export ENVVAULT_VAULT=/tmp/ev-dev/vault.db
export ENVVAULT_CONFIG_DIR=/tmp/ev-dev/cfg
```

## Environment variables

| Variable | Effect |
| --- | --- |
| `ENVVAULT_VAULT` | Vault database path (same as `--vault`) |
| `ENVVAULT_CONFIG_DIR` | Config/session directory override |
| `ENVVAULT_PASSWORD` | Non-interactive password (tests/CI only) |
| `ENVVAULT_SESSION_TTL` | Auto-lock timeout in seconds (default 900) |

## Project layout

```text
src/
├── main.rs        CLI (clap) — presentation only
├── lib.rs         library root
├── crypto.rs      Argon2id + XChaCha20-Poly1305 wrappers
├── vault.rs       core API: lifecycle, projects, secrets, audit, stats
├── store.rs       SQLite schema, pragmas, meta helpers
├── session.rs     unlocked-session persistence
└── error.rs       unified error type
tests/
└── vault_integration.rs
docs/
├── architecture.md
├── cryptography.md
├── security.md
├── threat-model.md
└── development.md
```

## Conventions

- The CLI never touches SQL or crypto directly — go through `Vault`.
- New secret-affecting actions must emit an audit entry **without values**.
- Every new feature needs a test; `cargo clippy -- -D warnings` must pass.
- Keep the CLI and any future GUI on the same core library.

## Release checklist

```bash
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo test
cargo build --release
```
