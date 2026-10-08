# Security

How EnvVault behaves operationally. The cryptographic design lives in
`cryptography.md`; the honest limitations live in `threat-model.md`.

## Password handling

- Read from the terminal without echo (`rpassword`).
- Never logged, never written to disk, never passed on the command line.
- `ENVVAULT_PASSWORD` exists for automation and tests; it is opt-in and
  documented as unsafe for interactive shells.
- Minimum 8 characters, confirmed twice at `init`.
- A wrong password fails AEAD authentication on the wrapped VEK and is
  reported as a single indistinguishable error.

## Key handling

- Keys live in `Zeroizing<Vec<u8>>`; memory is zeroized on drop.
- Key material exists in only three places: process memory, the wrapped form
  inside `vault.db`, and (while unlocked) `session.json`.
- `envvault lock` drops in-memory keys and deletes `session.json`.

## Session security

- Session file: `<config dir>/envvault/session.json`, mode `0600` on Unix.
- Sliding deadline: refreshed on every use, default 15 minutes.
- Bound to a vault path — a session for one vault cannot unlock another.
- `ENVVAULT_SESSION_TTL` overrides the timeout (seconds).
- Expired sessions are deleted on detection.

## Input validation

- Project / environment names are trimmed and lowercased; secrets are
  trimmed. Empty names are rejected.
- `.env` parsing reports line numbers on malformed input and never executes
  content.
- Secret values are treated as opaque bytes (UTF-8 not required) until an
  export forces a text representation.

## Dangerous operations

Explicit confirmation is required for:

| Operation | Prompt |
| --- | --- |
| `export` | "this will create a PLAINTEXT file containing N secrets" |
| `import` | warns it reads plaintext, states the source file is not deleted |
| `project delete` | deletes all nested secrets |
| `secret delete` | targets a specific secret |

Secrets are **never** displayed automatically: `list` shows metadata only,
`get` prints one value to stdout, `run` injects without printing.

## Audit log

Recorded actions: vault unlock, project/environment create+delete,
secret create+modify+delete+access (success and failure), import, export,
environment run.

Rules enforced in code and by tests:

- audit rows contain `time, action, resource, result` only;
- secret **values** never appear in a resource string;
- `tests/vault_integration.rs::audit_log_never_contains_values` fails the
  build if this regresses.

## Data at rest

- SQLite database with WAL journaling; every secret value is ciphertext.
- Backups (`envvault backup`) are byte copies of the encrypted database —
  no decryption step exists in the backup path.
- `import` never deletes the original plaintext file; the operator is told to
  remove it manually.

## Reporting

Found a problem? Please open an issue at
https://github.com/anomalyco/opencode/issues with the `security` label.
