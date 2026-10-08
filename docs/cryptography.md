# Cryptography

## Goals

- Encrypt every secret value at rest with authenticated encryption.
- Never derive an encryption key directly from the password.
- Allow future key rotation without re-encrypting the whole vault.
- Detect wrong passwords and tampering unambiguously.

## Key hierarchy

```text
Master Password
       │
       ▼
   Argon2id (random 16-byte salt)
       │
       ▼
 Key Encryption Key (KEK, 32 bytes)
       │
       ▼  XChaCha20-Poly1305, AAD = "envvault/vek"
 Vault Encryption Key (VEK, 32 bytes, random)
       │
       ▼  XChaCha20-Poly1305, AAD = secret id
   secret value ciphertext
```

The password never touches data encryption directly. The KEK only wraps the
VEK, which means:

- rotating the master password only re-wraps 32 bytes;
- a future key-rotation feature can re-wrap the VEK with a new key without
  touching any secret rows.

## Algorithms

| Purpose | Algorithm | Source |
| --- | --- | --- |
| Password KDF | Argon2id v1.3 | RustCrypto `argon2` |
| All encryption | XChaCha20-Poly1305 (AEAD) | RustCrypto `chacha20poly1305` |
| Randomness | OS CSPRNG via `rand` | `getrandom` |

### Argon2id parameters

| Parameter | Value |
| --- | --- |
| Memory | 64 MiB |
| Iterations | 3 |
| Parallelism | 4 |
| Output | 32 bytes |

Parameters are stored in the vault `meta` table as JSON, so they can be
increased later without breaking existing vaults (old vaults keep the
parameters they were created with).

### AEAD usage

- Every encryption uses a fresh random 24-byte nonce (XChaCha20's extended
  nonce makes random nonces safe at vault scale).
- **Associated data (AAD)** binds each ciphertext to its context:
  - the wrapped VEK uses `envvault/vek`;
  - each secret uses its own row id, so records cannot be swapped or
    re-pointed without failing authentication.
- Any authentication failure surfaces as a single opaque error: the operator
  cannot distinguish a wrong password from corrupted bytes (no oracle).

## Password policy

Minimum 8 characters (`crypto::validate_password`). Length beats composition
rules; a longer minimum can be raised in a future version for new vaults.

## What is stored where

| Location | Content |
| --- | --- |
| `meta` table | salt, KDF params, wrapped VEK + nonce |
| `secrets.ciphertext/nonce` | sealed secret values |
| `secrets.name/type/...` | plaintext metadata (deliberate) |
| `audit_log` | plaintext action records, never values |
| `session.json` | raw KEK + VEK, owner-only perms, auto-lock deadline |

The session file is the weakest link by design; it buys CLI convenience and
is documented in `docs/threat-model.md`.

## Verifying the design in code

- `src/crypto.rs` — primitive wrappers (`seal`, `open`, `derive_kek`) plus
  unit tests for round trips, tampering and wrong-AAD rejection.
- `tests/vault_integration.rs` — `values_are_ciphertext_at_rest` greps every
  file in the vault directory for a known plaintext value.
