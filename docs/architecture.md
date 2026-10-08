# Architecture

```text
                 EnvVault
                    │
             ┌──────┴──────┐
             │             │
           CLI          Desktop UI (planned)
             │             │
             └──────┬──────┘
                    │
              Core library (envvault)
                    │
      ┌─────────────┼─────────────┐
      │             │             │
   vault.rs     session.rs     crypto.rs
      │             │             │
      └─────────────┼─────────────┘
                    │
               store.rs (SQLite)
                    │
            encrypted vault.db
```

The CLI and the future desktop UI both link the same core library. Security
logic (key derivation, encryption, session handling) exists exactly once.

## Crates / modules

| Module | Responsibility |
| --- | --- |
| `src/crypto.rs` | Argon2id KDF, XChaCha20-Poly1305 seal/open, password policy |
| `src/vault.rs` | Core API: vault lifecycle, projects, environments, secrets, audit, stats |
| `src/store.rs` | SQLite connection pragmas, schema, meta table |
| `src/session.rs` | Unlocked-session persistence between CLI invocations |
| `src/error.rs` | Single error type shared by every layer |
| `src/main.rs` | CLI argument parsing and presentation only |

The CLI layer performs no cryptography and never touches SQL: it only calls
`Vault` methods and formats output.

## Data model

```text
projects
├── id, name, description, created_at, updated_at
│
environments (per project: development, production, ...)
│   ├── id, project_id, name, created_at, updated_at
│   │
    secrets (per environment)
│       ├── id, project_id, environment_id
│       ├── name, type, description        ← metadata, visible
│       ├── ciphertext, nonce              ← value, encrypted
│       ├── created_at, updated_at
│       └── version                        ← incremented on update
│
audit_log
    └── time, action, resource, result     ← never contains values

meta
    └── salt, kdf params, wrapped VEK, nonce, format version
```

Foreign keys are enforced (`PRAGMA foreign_keys = ON`), so deleting a project
cascades to its environments and secrets.

## Key material flow

1. `envvault init` generates a random salt and a random 32-byte Vault
   Encryption Key (VEK).
2. The master password is stretched with Argon2id into a Key Encryption Key
   (KEK); the KEK wraps the VEK; both wrapped values go into the `meta` table.
3. `envvault unlock` re-derives the KEK and unwraps the VEK. A wrong password
   fails authentication on the wrapped VEK, so it is detected immediately.
4. Unwrapped keys are kept only in memory (zeroized on drop) plus, for CLI
   continuity, in a session file with an auto-lock deadline.

## Session model

The CLI is stateless per invocation, so an unlocked session is persisted to
`<config>/envvault/session.json` with owner-only permissions. The deadline is
sliding: every command that uses the session pushes the auto-lock timeout
forward (default 15 minutes, override with `ENVVAULT_SESSION_TTL` seconds).
`envvault lock` deletes the file. See `docs/threat-model.md` for the
limitations this implies.

## Design decisions

- **SQLite over a custom format** — mature, transactional, easy to inspect,
  and maps directly onto the spec's conceptual schema.
- **Metadata in plaintext** — names and types stay readable so the CLI/UI can
  list secrets while the vault is locked and so backups remain browsable.
  Values are always ciphertext. This is a deliberate threat-model choice, see
  `docs/threat-model.md`.
- **No global state in the core** — `Vault` owns its connection and key
  material; tests create throwaway vaults freely.
- **Pure-Rust crypto stack** — `argon2`, `chacha20poly1305` (RustCrypto) and
  `rusqlite` with a bundled SQLite, so there is no system OpenSSL dependency.
