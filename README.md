# EnvVault

**Secure environment and credential management for developers.**

Store API keys, environment variables, database credentials and SSH keys in an
encrypted local vault. Inject secrets directly into processes without
maintaining plaintext `.env` files.

```text
         .env files
             ↓
      ┌─────────────┐
      │   EnvVault  │
      │             │
      │ Encrypted   │
      │ SSH         │
      │ Envs        │
      │ Run         │
      └──────┬──────┘
             ↓
         Your app
```

## Why

Instead of scattering secrets across `.env` files, shell profiles and home
directories:

```text
.env
├── API_KEY=...
├── DATABASE_URL=...
├── JWT_SECRET=...
└── STRIPE_KEY=...
```

everything lives in one encrypted vault, and secrets are decrypted only when a
process actually needs them:

```bash
envvault run my-api --env development -- npm run dev
```

No plaintext `.env` file is ever written.

## Status (v0.1)

| Feature | Status |
| --- | --- |
| Vault creation / master password | ✅ |
| Argon2id + XChaCha20-Poly1305 key hierarchy | ✅ |
| Encrypted SQLite storage (ciphertext at rest) | ✅ |
| Lock / unlock with sliding session timeout | ✅ |
| Projects, environments, secrets | ✅ |
| Full CLI | ✅ |
| `run` command with env injection | ✅ |
| `.env` import / export with confirmation | ✅ |
| Encrypted backup | ✅ |
| Audit log (never records values) | ✅ |
| Desktop UI | ⏳ planned (Tauri) |
| SSH key management | ⏳ planned (v0.3) |

## Install

```bash
cargo install --path .
```

## Quick start

```bash
envvault init
envvault project create my-api
envvault env create my-api development

# value is read from stdin, never echoed
echo -n "sk-..." | envvault set my-api API_KEY --env development --type api-key

envvault list my-api --env development
envvault get my-api API_KEY --env development

envvault run my-api --env development -- npm run dev
```

## Commands

```bash
envvault init                          # create an encrypted vault
envvault unlock / lock / status        # session control

envvault project create|list|delete
envvault env create|list
envvault secret set|get|list|delete    # aliases: set, get, list

envvault run <project> --env <env> -- <command>
envvault import .env --project my-api  # warns, never deletes the source
envvault export my-api --env dev       # plaintext on purpose, confirms twice
envvault backup ./backup.db            # stays encrypted
envvault audit                         # actions only, no values
```

## How it works

```text
Master Password
       │
    Argon2id ──► Key Encryption Key
       │
   wraps ──► Vault Encryption Key
                  │
       XChaCha20-Poly1305 seals each secret value
                  │
            SQLite (ciphertext at rest)
```

The database holds ciphertext for every secret value; only metadata (names,
types, timestamps) is readable without the key. See
[docs/cryptography.md](docs/cryptography.md) for the full design and
[docs/threat-model.md](docs/threat-model.md) for what EnvVault does and does
not protect against.

## Documentation

```text
docs/
├── architecture.md
├── cryptography.md
├── security.md
├── threat-model.md
└── development.md
```

## License

TBD
