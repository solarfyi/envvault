# Threat model

EnvVault is a local-first secrets manager. Being explicit about what it does
and does not protect is more useful than claiming to protect everything.

## Assets

1. Secret values (API keys, tokens, passwords, database URLs).
2. SSH private keys (from v0.3).
3. The metadata graph: which projects/secrets exist and when they changed.

## Protects against

| Threat | Mechanism |
| --- | --- |
| Someone reading the vault database | Every value is sealed with XChaCha20-Poly1305; only the KEK-holder can unwrap the VEK |
| Accidental `.env` commits | Secrets live in the vault; `run` injects without writing files |
| Plaintext secrets in project directories | Import warns and tells you the source file stays behind; export requires explicit confirmation |
| Backup / file theft | Backups are byte-copies of the encrypted database; `session.json` is not included |
| Unauthorized access while locked | No key material on disk beyond the password-wrapped VEK |
| Tampering / record swapping | AEAD authentication with per-secret AAD (row id) |
| Secrets leaking into logs | Audit records contain action + resource name only; tests assert values never appear |

## Does NOT fully protect against

| Threat | Why |
| --- | --- |
| Malware running as the same user | `session.json` holds unwrapped keys while unlocked; same-user code can read it |
| A compromised operating system | Anything that can read process memory or hook syscalls wins |
| A process already receiving injected env vars | The child process legitimately holds the values |
| Memory extraction / cold-boot attacks | Keys are zeroized on drop, but a live process still holds them |
| Someone watching the screen during a reveal | UI-level concern, not a crypto one |
| Metadata disclosure | Project names, secret names and audit history are plaintext by design |

## Trusted computing base

- The OS account running EnvVault.
- The Rust toolchain and crates pinned in `Cargo.lock`.
- Bundled SQLite (`rusqlite` with `bundled` feature).

## Deliberate design trade-offs

**Plaintext metadata.** Secret names and types are readable without the
password so the CLI and dashboard can show structure while locked. An
attacker with the database learns *that* you have `STRIPE_KEY`, not its
value. If your threat model includes that, encrypting metadata is a possible
future mode.

**Session file instead of a daemon.** Holding keys in a background process
would be strictly better, but a session file keeps the CLI simple and
cross-platform. The file is owner-only, path-bound to the vault, and expires
on a sliding deadline (default 15 minutes).

**Audit log is plaintext.** It contains no secret values, so it is safe to
leave readable; encrypting it would prevent triage while the vault is locked.

## Recommended operator practices

- Use a long, unique master password (a passphrase of 5+ random words).
- Lock the vault (`envvault lock`) on shared machines.
- Don't set `ENVVAULT_SESSION_TTL` to a large value on laptops.
- Treat `envvault export` as the most dangerous command in the tool.
- Keep backups of `vault.db` — there is no recovery without the password.
