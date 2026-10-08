Absolutely. I’d make the UI a **desktop-first developer vault**, with the CLI still being a first-class interface. The main selling point is: **manage secrets securely without scattering `.env` files and SSH keys around your machine.**

# EnvVault — Product Specification

**Version:** 1.0  
**Type:** Local-first developer secrets & environment manager  
**Primary platform:** Windows + Linux  
**Core language:** Go  
**UI:** Desktop application  
**CLI:** Yes  
**Storage:** Local encrypted vault  
**License:** TBD

---

## 1. Product vision

**EnvVault** is a secure local-first application for managing:

- Environment variables
- API keys
- Access tokens
- Passwords
- Database credentials
- SSH private/public keys
- Certificates
- Project-specific secrets

Instead of storing sensitive configuration in plaintext `.env` files, developers store everything inside an encrypted vault and inject secrets directly into applications when needed.

### Example

Instead of:

```text
.env
├── API_KEY=...
├── DATABASE_URL=...
├── JWT_SECRET=...
└── STRIPE_KEY=...
```

The developer uses:

```bash
envvault run my-api --env development -- npm run dev
```

EnvVault decrypts the required secrets and provides them to the process without creating a plaintext `.env` file.

---

# 2. Design principles

### Security first

Sensitive values should be encrypted at rest and never unnecessarily exposed.

### Local-first

The vault works completely offline.

There is **no mandatory cloud account or server**.

### Developer-focused

CLI commands and automation are as important as the graphical interface.

### Minimal exposure

Secrets should only be decrypted when necessary.

### Explicit actions

Dangerous operations such as exporting the entire vault require deliberate confirmation.

### Auditable

The application records security-relevant actions without recording secret values.

---

# 3. Main UI

The application should use a dark, modern developer-tool aesthetic.

```text
┌──────────────────────────────────────────────────────────────────────┐
│  ◈ ENVVAULT                                      ● Vault Unlocked    │
├───────────────┬──────────────────────────────────────────────────────┤
│               │                                                      │
│  OVERVIEW     │  Dashboard                                           │
│               │                                                      │
│  ▣ Dashboard  │  ┌────────────────┐  ┌───────────────────────────┐ │
│               │  │ Projects       │  │ Vault                     │ │
│  PROJECTS     │  │                │  │                           │ │
│               │  │      7         │  │ ● Unlocked                │ │
│  ▸ Projects  │  │                │  │                           │ │
│               │  └────────────────┘  │ Encryption: XChaCha20      │ │
│  SECURITY     │                      │ KDF: Argon2id              │ │
│               │  ┌────────────────┐  └───────────────────────────┘ │
│  ◈ SSH Keys   │  │ Secrets        │                                │
│  ◈ Audit Log  │  │                │  Recent Activity              │
│  ◈ Sessions   │  │     42         │  ───────────────────────────   │
│               │  └────────────────┘  14:32 Secret accessed         │
│  SETTINGS     │                      14:29 Vault unlocked           │
│               │                      14:17 Project created          │
│  ⚙ Settings   │                                                      │
│               │                                                      │
├───────────────┴──────────────────────────────────────────────────────┤
│  EnvVault v0.1.0                              localhost / local      │
└──────────────────────────────────────────────────────────────────────┘
```

---

# 4. Dashboard

The dashboard gives an overview without exposing secret values.

### Cards

```text
Projects       Secrets       SSH Keys       Vault
    7             42             5          ● Unlocked
```

### Recent activity

```text
14:32   API key accessed
14:29   Vault unlocked
14:17   Project created
13:52   SSH key generated
13:44   Environment updated
```

No secret values appear in the dashboard.

---

# 5. Projects screen

Projects are the main organizational unit.

```text
┌─────────────────────────────────────────────────────────────────┐
│ Projects                                      + New Project     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Search projects...                                             │
│                                                                 │
│  PROJECT             ENVIRONMENTS       SECRETS       STATUS     │
│  ─────────────────────────────────────────────────────────────  │
│  ◈ Buddy              3                  14           Active     │
│  ◈ Website            2                   8           Active     │
│  ◈ Discord Bot        2                   6           Active     │
│  ◈ Homelab            1                   9           Active     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Clicking a project opens its detail page.

---

# 6. Project detail

```text
┌─────────────────────────────────────────────────────────────────┐
│ ← Projects     Buddy                              • Active      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Overview    Secrets    Environments    SSH    Activity         │
│  ─────────────────────────────────────────────────────────────  │
│                                                                 │
│  Environments                                                   │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ development                                      12 vars  │ │
│  │ Last modified: 8 minutes ago                    ● Ready    │ │
│  │                                                           │ │
│  │                              [Open] [Run]                 │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ production                                        9 vars  │ │
│  │ Last modified: yesterday                        ● Ready    │ │
│  │                                                           │ │
│  │                              [Open] [Run]                 │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

# 7. Secret browser

Secrets should **never be displayed automatically**.

```text
┌─────────────────────────────────────────────────────────────────┐
│ Buddy / development                              + Add Secret   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Search secrets...                                              │
│                                                                 │
│  NAME                 TYPE              UPDATED                  │
│  ─────────────────────────────────────────────────────────────  │
│  API_KEY              API Key           4 min ago                │
│  DATABASE_URL         Database          2 hours ago              │
│  JWT_SECRET           Secret            yesterday                │
│  DEBUG                Variable         3 days ago                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

The actual value is represented as:

```text
••••••••••••••••••
```

---

# 8. Secret viewer

When the user explicitly chooses to reveal a secret:

```text
┌──────────────────────────────────────────────┐
│ API_KEY                               [×]    │
├──────────────────────────────────────────────┤
│                                              │
│ Type                                         │
│ API Key                                      │
│                                              │
│ Value                                        │
│ ┌──────────────────────────────────────────┐ │
│ │ ••••••••••••••••••••••••••••••••••••• │ │
│ └──────────────────────────────────────────┘ │
│                                              │
│          [ Reveal ]   [ Copy ]               │
│                                              │
│ Created:       Oct 8, 2026                   │
│ Modified:      Oct 8, 2026                   │
│ Version:       4                             │
│                                              │
│ ⚠ Revealing this secret will be audited      │
└──────────────────────────────────────────────┘
```

Clipboard functionality should have an automatic clearing option.

Example:

```text
Copied — clipboard will clear in 20 seconds.
```

---

# 9. Add secret

```text
┌──────────────────────────────────────────────┐
│ Add Secret                                   │
├──────────────────────────────────────────────┤
│                                              │
│ Name                                         │
│ [ API_KEY_______________________________ ]   │
│                                              │
│ Type                                         │
│ [ API Key                              ▼ ]   │
│                                              │
│ Value                                        │
│ [ ••••••••••••••••••••••••••••••••••••• ]   │
│                                              │
│ Environment                                  │
│ [ development                          ▼ ]   │
│                                              │
│ Description                                  │
│ [ OpenAI API authentication key________ ]    │
│                                              │
│                         [Cancel] [Save]      │
└──────────────────────────────────────────────┘
```

---

# 10. Environment runner

This is one of the most important UI features.

```text
┌──────────────────────────────────────────────────────────────┐
│ Run Environment                                               │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│ Project                                                      │
│ [ Buddy                                      ▼ ]             │
│                                                              │
│ Environment                                                  │
│ [ development                                ▼ ]             │
│                                                              │
│ Command                                                      │
│ [ npm run dev_______________________________ ]               │
│                                                              │
│ Secrets available: 14                                        │
│                                                              │
│ ☑ Inject environment variables                               │
│ ☐ Inject SSH agent                                           │
│ ☐ Show command output                                        │
│                                                              │
│                              [ Run ]                          │
└──────────────────────────────────────────────────────────────┘
```

The equivalent CLI:

```bash
envvault run buddy \
  --env development \
  -- npm run dev
```

---

# 11. SSH key manager

Separate section for SSH credentials.

```text
┌─────────────────────────────────────────────────────────────────┐
│ SSH Keys                                        + Add SSH Key   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  NAME              TYPE          FINGERPRINT                    │
│  ─────────────────────────────────────────────────────────────  │
│  github             Ed25519       SHA256:••••••••••             │
│  homelab            Ed25519       SHA256:••••••••••             │
│  production         RSA           SHA256:••••••••••             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Private keys remain encrypted.

The fingerprint can safely be displayed because it isn't the private key.

---

# 12. SSH key detail

```text
┌───────────────────────────────────────────────┐
│ github                                        │
├───────────────────────────────────────────────┤
│                                               │
│ Type              Ed25519                     │
│                                               │
│ Fingerprint                                    │
│ SHA256:xxxxxxxxxxxxxxxxxxxxxxxx               │
│                                               │
│ Public key                                     │
│ ssh-ed25519 AAAA...                            │
│                                               │
│ Private key                                    │
│ 🔒 Encrypted                                   │
│                                               │
│ Created           Oct 2, 2026                  │
│ Last accessed     Today                        │
│                                               │
│ [Use] [Rotate] [Delete]                       │
└───────────────────────────────────────────────┘
```

---

# 13. Audit log

```text
┌──────────────────────────────────────────────────────────────────┐
│ Audit Log                                                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│ TIME       ACTION              RESOURCE             RESULT       │
│ ───────────────────────────────────────────────────────────────  │
│ 14:32      Secret accessed     Buddy/API_KEY        Success      │
│ 14:29      Vault unlocked      —                    Success      │
│ 14:17      Project created     Buddy                Success      │
│ 13:52      SSH key generated   github               Success      │
│ 13:44      Secret modified     Buddy/JWT_SECRET     Success      │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Never log the secret itself.**

---

# 14. Lock screen

When the vault is locked:

```text
┌───────────────────────────────────────────────┐
│                                               │
│                    ◈                          │
│                                               │
│                  EnvVault                     │
│                                               │
│              Vault Locked                     │
│                                               │
│     Master Password                           │
│     ┌─────────────────────────────────────┐   │
│     │ •••••••••••••••••••••••••          │   │
│     └─────────────────────────────────────┘   │
│                                               │
│                  [ Unlock ]                   │
│                                               │
└───────────────────────────────────────────────┘
```

Optional biometric/OS credential integration can be a later feature.

---

# 15. Settings

```text
Settings

GENERAL
├── Start with system
├── Auto-lock timeout
├── Default project
└── Confirm destructive actions

SECURITY
├── Change master password
├── Lock vault
├── Session timeout
├── Clipboard timeout
└── Security notifications

STORAGE
├── Vault location
├── Backup vault
└── Restore vault

CLI
├── Shell integration
├── Default editor
└── Command behavior
```

---

# 16. Data architecture

Conceptually:

```text
                     EnvVault
                        │
             ┌──────────┴──────────┐
             │                     │
           GUI                    CLI
             │                     │
             └──────────┬──────────┘
                        │
                    Core API
                        │
          ┌─────────────┼─────────────┐
          │             │             │
       Vault         Projects        SSH
          │             │             │
          └─────────────┼─────────────┘
                        │
                    Crypto Layer
                        │
                  Encrypted Storage
```

The GUI and CLI should use the **same core library**, rather than implementing security logic twice.

---

# 17. Security architecture

### Encryption

Use authenticated encryption.

Recommended:

**XChaCha20-Poly1305**

Each encrypted object should have its own nonce.

### Password derivation

Use:

**Argon2id**

with a randomly generated salt.

### Key hierarchy

Don't directly use the password as the encryption key.

```text
Master Password
       │
       ▼
    Argon2id
       │
       ▼
  Key Encryption Key
       │
       ▼
  Vault Encryption Key
       │
       ▼
Encrypted secrets
```

This makes future key rotation much easier.

---

# 18. Vault storage

The database itself should contain ciphertext rather than plaintext secrets.

For example:

```text
secrets

id
project_id
environment_id
name
type
ciphertext
nonce
created_at
updated_at
version
```

Metadata such as the secret name may remain visible depending on the chosen threat model.

The **value itself must be encrypted**.

---

# 19. Threat model

The documentation should explicitly explain what EnvVault protects against.

### Protects against

- Someone reading the vault database
- Accidental `.env` commits
- Plaintext secrets sitting in project directories
- Basic backup/file theft
- Unauthorized access while the vault is locked

### Does NOT fully protect against

- Malware running as the same user
- A compromised operating system
- A process that already has access to injected environment variables
- Memory extraction from a compromised machine
- Someone watching the screen while a secret is revealed

This honesty makes the project look **more security-conscious**, not less.

---

# 20. CLI

The CLI remains fully functional without the GUI.

```bash
envvault init

envvault unlock
envvault lock

envvault project create my-api
envvault project list
envvault project delete my-api

envvault env create my-api development
envvault env list my-api

envvault set my-api API_KEY
envvault get my-api API_KEY
envvault list my-api

envvault run my-api --env development -- npm run dev

envvault ssh list
envvault ssh add github
envvault ssh generate github

envvault audit
envvault backup
```

---

# 21. Import/export

### Import

Support:

```bash
envvault import .env
```

But show a warning:

```text
⚠ Importing this file will read plaintext secrets.

Source:
./.env

12 secrets detected.

After import, EnvVault will not delete the original file.

Continue? [y/N]
```

### Export

Exports should be deliberately harder:

```bash
envvault export my-api --env development
```

Require confirmation and clearly warn:

```text
⚠ This will create a PLAINTEXT file containing 14 secrets.

Continue? [y/N]
```

---

# 22. Backup

The encrypted vault can be safely backed up:

```bash
envvault backup ./backup.envvault
```

Because the backup remains encrypted, copying it to another machine doesn't expose the secrets by itself.

---

# 23. MVP

The first release should **not** try to build everything.

### v0.1

- [ ] Vault creation
- [ ] Master password
- [ ] Argon2id
- [ ] Encrypted storage
- [ ] Lock/unlock
- [ ] Projects
- [ ] Environments
- [ ] Secrets
- [ ] CLI
- [ ] Basic desktop UI

### v0.2

- [ ] `envvault run`
- [ ] `.env` import
- [ ] Clipboard protection
- [ ] Audit log
- [ ] Secret versions

### v0.3

- [ ] SSH key management
- [ ] SSH key generation
- [ ] SSH agent integration
- [ ] Backups
- [ ] Secret rotation

### v1.0

- [ ] Polished UI
- [ ] Security audit/testing
- [ ] Fuzzing
- [ ] Cross-platform builds
- [ ] Documentation
- [ ] Threat model
- [ ] Recovery/backup workflow

---

# 24. Portfolio presentation

The GitHub README should lead with something like:

> **EnvVault — Secure environment and credential management for developers.**
>
> Store API keys, environment variables, database credentials and SSH keys in an encrypted local vault. Inject secrets directly into processes without maintaining plaintext `.env` files.

Then show:

```text
             .env files
                 ↓
          ┌─────────────┐
          │   EnvVault  │
          │             │
          │ 🔐 Encrypted│
          │ 🗝 SSH      │
          │ ⚙ Envs      │
          │ 🚀 Run      │
          └──────┬──────┘
                 ↓
             Your app
```

And the repo should have dedicated documentation:

```text
docs/
├── architecture.md
├── security.md
├── threat-model.md
├── cryptography.md
└── development.md
```

That combination — **working application + CLI + polished UI + cryptographic design + threat model + architecture docs** — would make this a substantially stronger portfolio piece than a generic password manager or `.env editor.
