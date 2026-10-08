//! Unlocked-session persistence between CLI invocations.
//!
//! The session file holds key material with owner-only permissions. It
//! protects the vault database against theft and backup exposure, but NOT
//! against malware running as the same user — see docs/threat-model.md.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::vault::{Vault, config_dir};

/// Sliding auto-lock timeout; refreshed on every command that uses it.
const DEFAULT_TTL_SECS: i64 = 15 * 60;

#[derive(Serialize, Deserialize)]
struct SessionFile {
    vault_path: String,
    kek: String,
    vek: String,
    deadline: String,
}

pub fn session_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("session.json"))
}

fn ttl() -> Duration {
    let secs = std::env::var("ENVVAULT_SESSION_TTL")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_TTL_SECS);
    Duration::from_secs(secs as u64)
}

fn deadline() -> String {
    (Utc::now() + chrono::Duration::from_std(ttl()).unwrap_or_default())
        .to_rfc3339()
        .to_string()
}

/// Persists unlocked key material for subsequent commands.
pub fn save(vault_path: &Path, kek: &[u8], vek: &[u8]) -> Result<()> {
    let path = session_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let session = SessionFile {
        vault_path: vault_path.display().to_string(),
        kek: hex::encode(kek),
        vek: hex::encode(vek),
        deadline: deadline(),
    };
    let data = serde_json::to_vec_pretty(&session)
        .map_err(|e| Error::Invalid(format!("serializing session: {e}")))?;
    std::fs::write(&path, data)?;
    restrict_permissions(&path);
    Ok(())
}

/// Removes any active session (vault lock).
pub fn clear() -> Result<()> {
    let path = session_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Restores an unlocked vault from the active session file.
///
/// Returns [`Error::NoSession`] when no session exists and
/// [`Error::SessionExpired`] after the auto-lock deadline has passed.
pub fn load(expected_vault: Option<&Path>) -> Result<Vault> {
    let path = session_path()?;
    let data = std::fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::NoSession
        } else {
            Error::Io(e)
        }
    })?;

    let session: SessionFile = serde_json::from_slice(&data).map_err(|_| Error::NoSession)?;

    let deadline = DateTime::parse_from_rfc3339(&session.deadline)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| Error::NoSession)?;
    if Utc::now() > deadline {
        let _ = clear();
        return Err(Error::SessionExpired);
    }

    let vault_path = PathBuf::from(&session.vault_path);
    if expected_vault.is_some_and(|expected| expected != vault_path) {
        return Err(Error::NoSession);
    }

    let kek = hex::decode(&session.kek).map_err(|_| Error::NoSession)?;
    let vek = hex::decode(&session.vek).map_err(|_| Error::NoSession)?;
    let vault = Vault::reopen(&vault_path, kek, vek)?;

    // Sliding expiry: refresh the deadline while the session is in use.
    let _ = save(
        vault.path(),
        vault.key_material().map(|(k, _)| k).unwrap_or_default(),
        vault.key_material().map(|(_, v)| v).unwrap_or_default(),
    );

    Ok(vault)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}
