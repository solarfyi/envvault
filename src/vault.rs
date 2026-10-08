//! Core vault API shared by the CLI and (later) the desktop UI.

use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::crypto::{self, AAD_VEK, KEY_LEN, KdfParams, SALT_LEN};
use crate::error::{Error, Result};
use crate::session;
use crate::store;

const META_VERSION: &str = "version";
const META_SALT: &str = "salt";
const META_KDF: &str = "kdf";
const META_WRAPPED_VEK: &str = "wrapped_vek";
const META_VEK_NONCE: &str = "vek_nonce";
const META_CREATED_AT: &str = "created_at";
const VAULT_FORMAT_VERSION: &str = "1";

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn new_id() -> String {
    hex::encode(crypto::random_bytes::<8>())
}

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    matches!(err, rusqlite::Error::SqliteFailure(e, _)
        if e.to_string().contains("UNIQUE constraint failed")
            || e.code == rusqlite::ErrorCode::ConstraintViolation)
}

/// Project is the main organizational unit of a vault.
#[derive(Debug, Clone)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
    pub environments: i64,
    pub secrets: i64,
}

/// Environment groups secrets for a project (development, production, ...).
#[derive(Debug, Clone)]
pub struct Environment {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub secrets: i64,
}

/// Secret metadata. The value only ever exists decrypted in memory.
#[derive(Debug, Clone)]
pub struct Secret {
    pub id: String,
    pub project_id: String,
    pub environment_id: String,
    pub name: String,
    pub secret_type: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
    pub version: i64,
}

/// Audit entry. Never contains secret values.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub time: String,
    pub action: String,
    pub resource: String,
    pub result: String,
}

/// Dashboard counters; exposes no secret values.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub projects: i64,
    pub environments: i64,
    pub secrets: i64,
    pub ssh_keys: i64,
    pub unlocked: bool,
}

pub struct Vault {
    path: PathBuf,
    conn: Connection,
    kek: Option<Zeroizing<Vec<u8>>>,
    vek: Option<Zeroizing<Vec<u8>>>,
}

impl Vault {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_unlocked(&self) -> bool {
        self.vek.is_some()
    }

    pub(crate) fn key_material(&self) -> Option<(&[u8], &[u8])> {
        match (&self.kek, &self.vek) {
            (Some(kek), Some(vek)) => Some((kek.as_slice(), vek.as_slice())),
            _ => None,
        }
    }

    pub fn default_path() -> Result<PathBuf> {
        Ok(config_dir()?.join("vault.db"))
    }

    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Creates a new encrypted vault at `path`, protected by `password`.
    /// The returned vault is unlocked.
    pub fn create(path: &Path, password: &[u8]) -> Result<Vault> {
        if Self::exists(path) {
            return Err(Error::VaultExists(path.display().to_string()));
        }
        crypto::validate_password(password)?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = store::open(path)?;
        store::create_schema(&conn)?;

        let salt = crypto::random_bytes::<SALT_LEN>();
        let vek = crypto::random_bytes::<KEY_LEN>();
        let kdf = KdfParams::default();
        let kek = crypto::derive_kek(password, &salt, &kdf)?;
        let (wrapped, nonce) = crypto::seal(kek.as_slice(), &vek, AAD_VEK)?;

        store::meta_set(&conn, META_VERSION, VAULT_FORMAT_VERSION)?;
        store::meta_set(&conn, META_SALT, &hex::encode(salt))?;
        store::meta_set(
            &conn,
            META_KDF,
            &serde_json::to_string(&kdf).expect("kdf serializes"),
        )?;
        store::meta_set(&conn, META_WRAPPED_VEK, &hex::encode(&wrapped))?;
        store::meta_set(&conn, META_VEK_NONCE, &hex::encode(nonce))?;
        store::meta_set(&conn, META_CREATED_AT, &now())?;

        Ok(Vault {
            path: path.to_path_buf(),
            conn,
            kek: Some(kek),
            vek: Some(Zeroizing::new(vek.to_vec())),
        })
    }

    /// Unlocks the vault with the master password.
    pub fn open(path: &Path, password: &[u8]) -> Result<Vault> {
        if !Self::exists(path) {
            return Err(Error::VaultNotFound);
        }
        let conn = store::open(path)?;

        let salt_hex = store::meta_get(&conn, META_SALT)?
            .ok_or_else(|| Error::Invalid("vault meta corrupted: missing salt".into()))?;
        let kdf_json = store::meta_get(&conn, META_KDF)?
            .ok_or_else(|| Error::Invalid("vault meta corrupted: missing kdf".into()))?;
        let wrapped_hex = store::meta_get(&conn, META_WRAPPED_VEK)?
            .ok_or_else(|| Error::Invalid("vault meta corrupted: missing key".into()))?;
        let nonce_hex = store::meta_get(&conn, META_VEK_NONCE)?
            .ok_or_else(|| Error::Invalid("vault meta corrupted: missing nonce".into()))?;

        let salt = decode_hex(&salt_hex, "salt")?;
        let wrapped = decode_hex(&wrapped_hex, "wrapped key")?;
        let nonce = decode_hex(&nonce_hex, "nonce")?;
        let kdf: KdfParams = serde_json::from_str(&kdf_json)
            .map_err(|_| Error::Invalid("vault meta corrupted: bad kdf params".into()))?;

        let kek = crypto::derive_kek(password, &salt, &kdf)?;
        let vek = crypto::open(kek.as_slice(), &wrapped, &nonce, AAD_VEK)
            .map_err(|_| Error::WrongPassword)?;

        Ok(Vault {
            path: path.to_path_buf(),
            conn,
            kek: Some(kek),
            vek: Some(Zeroizing::new(vek)),
        })
    }

    /// Restores an unlocked vault from stored key material (an active session).
    pub(crate) fn reopen(path: &Path, kek: Vec<u8>, vek: Vec<u8>) -> Result<Vault> {
        if !Self::exists(path) {
            return Err(Error::VaultNotFound);
        }
        let conn = store::open(path)?;
        Ok(Vault {
            path: path.to_path_buf(),
            conn,
            kek: Some(Zeroizing::new(kek)),
            vek: Some(Zeroizing::new(vek)),
        })
    }

    /// Persists the unlocked key material for subsequent CLI invocations.
    pub fn save_session(&self) -> Result<()> {
        let (kek, vek) = self.key_material().ok_or(Error::Locked)?;
        session::save(self.path(), kek, vek)
    }

    /// Locks the vault, destroying in-memory key material.
    pub fn lock(&mut self) {
        self.kek = None;
        self.vek = None;
    }

    fn require_unlocked(&self) -> Result<()> {
        if self.vek.is_some() {
            Ok(())
        } else {
            Err(Error::Locked)
        }
    }

    // --- Projects ------------------------------------------------------------

    pub fn create_project(&self, name: &str, description: &str) -> Result<Project> {
        self.require_unlocked()?;
        let name = normalize(name);
        if name.is_empty() {
            return Err(Error::Invalid("project name is required".into()));
        }
        let id = new_id();
        let ts = now();
        let res = self.conn.execute(
            "INSERT INTO projects (id, name, description, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, name, description, ts, ts],
        );
        match res {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                return Err(Error::AlreadyExists(format!("project '{name}'")));
            }
            Err(e) => return Err(e.into()),
        }
        self.audit("Project created", &name, "success");
        Ok(Project {
            id,
            name: name.to_string(),
            description: description.to_string(),
            created_at: ts.clone(),
            updated_at: ts,
            environments: 0,
            secrets: 0,
        })
    }

    pub fn list_projects(&self) -> Result<Vec<Project>> {
        self.require_unlocked()?;
        let mut stmt = self.conn.prepare(
            "SELECT p.id, p.name, p.description, p.created_at, p.updated_at,
                    (SELECT COUNT(*) FROM environments e WHERE e.project_id = p.id),
                    (SELECT COUNT(*) FROM secrets s WHERE s.project_id = p.id)
             FROM projects p ORDER BY p.name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Project {
                id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                environments: row.get(5)?,
                secrets: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_project(&self, name_or_id: &str) -> Result<Project> {
        self.require_unlocked()?;
        let normalized = normalize(name_or_id);
        let row = self
            .conn
            .query_row(
                "SELECT id, name, description, created_at, updated_at
                 FROM projects WHERE name = ?1 OR id = ?2",
                params![normalized, name_or_id],
                |row| {
                    Ok(Project {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        description: row.get(2)?,
                        created_at: row.get(3)?,
                        updated_at: row.get(4)?,
                        environments: 0,
                        secrets: 0,
                    })
                },
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("project '{name_or_id}'")))
    }

    pub fn delete_project(&self, name_or_id: &str) -> Result<()> {
        self.require_unlocked()?;
        let project = self.get_project(name_or_id)?;
        self.conn
            .execute("DELETE FROM projects WHERE id = ?1", params![project.id])?;
        self.audit("Project deleted", &project.name, "success");
        Ok(())
    }

    // --- Environments --------------------------------------------------------

    pub fn create_environment(&self, project: &str, env: &str) -> Result<Environment> {
        self.require_unlocked()?;
        let project = self.get_project(project)?;
        let name = normalize(env);
        if name.is_empty() {
            return Err(Error::Invalid("environment name is required".into()));
        }
        let id = new_id();
        let ts = now();
        let res = self.conn.execute(
            "INSERT INTO environments (id, project_id, name, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, project.id, name, ts, ts],
        );
        match res {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => {
                return Err(Error::AlreadyExists(format!("environment '{name}'")));
            }
            Err(e) => return Err(e.into()),
        }
        self.audit(
            "Environment created",
            &format!("{}/{}", project.name, name),
            "success",
        );
        Ok(Environment {
            id,
            project_id: project.id,
            name,
            created_at: ts.clone(),
            updated_at: ts,
            secrets: 0,
        })
    }

    pub fn list_environments(&self, project: &str) -> Result<Vec<Environment>> {
        self.require_unlocked()?;
        let project = self.get_project(project)?;
        let mut stmt = self.conn.prepare(
            "SELECT e.id, e.project_id, e.name, e.created_at, e.updated_at,
                    (SELECT COUNT(*) FROM secrets s WHERE s.environment_id = e.id)
             FROM environments e WHERE e.project_id = ?1 ORDER BY e.name",
        )?;
        let rows = stmt.query_map(params![project.id], |row| {
            Ok(Environment {
                id: row.get(0)?,
                project_id: row.get(1)?,
                name: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                secrets: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get_environment(&self, project: &str, env: &str) -> Result<Environment> {
        self.require_unlocked()?;
        let project = self.get_project(project)?;
        let name = normalize(env);
        let row = self
            .conn
            .query_row(
                "SELECT id, project_id, name, created_at, updated_at
                 FROM environments WHERE project_id = ?1 AND name = ?2",
                params![project.id, name],
                |row| {
                    Ok(Environment {
                        id: row.get(0)?,
                        project_id: row.get(1)?,
                        name: row.get(2)?,
                        created_at: row.get(3)?,
                        updated_at: row.get(4)?,
                        secrets: 0,
                    })
                },
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound(format!("environment '{env}'")))
    }

    // --- Secrets -------------------------------------------------------------

    /// Creates or updates a secret. The value is sealed before it touches disk.
    pub fn set_secret(
        &self,
        project: &str,
        env: &str,
        name: &str,
        secret_type: &str,
        description: &str,
        value: &[u8],
    ) -> Result<Secret> {
        self.require_unlocked()?;
        let environment = self.get_environment(project, env)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Invalid("secret name is required".into()));
        }
        let secret_type = if secret_type.is_empty() {
            "secret"
        } else {
            secret_type
        };
        let vek = self.vek.as_ref().ok_or(Error::Locked)?;

        let existing = self.find_secret(&environment.id, name)?;
        let ts = now();

        match existing {
            None => {
                let id = new_id();
                let (ct, nonce) = crypto::seal(vek.as_slice(), value, id.as_bytes())?;
                let res = self.conn.execute(
                    "INSERT INTO secrets (id, project_id, environment_id, name, type, description,
                                          ciphertext, nonce, created_at, updated_at, version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)",
                    params![
                        id,
                        environment.project_id,
                        environment.id,
                        name,
                        secret_type,
                        description,
                        ct,
                        nonce.as_slice(),
                        ts,
                        ts
                    ],
                );
                match res {
                    Ok(_) => {}
                    Err(e) if is_unique_violation(&e) => {
                        return Err(Error::AlreadyExists(format!("secret '{name}'")));
                    }
                    Err(e) => return Err(e.into()),
                }
                self.audit("Secret created", &format!("{project}/{name}"), "success");
                Ok(Secret {
                    id,
                    project_id: environment.project_id,
                    environment_id: environment.id,
                    name: name.to_string(),
                    secret_type: secret_type.to_string(),
                    description: description.to_string(),
                    created_at: ts.clone(),
                    updated_at: ts,
                    version: 1,
                })
            }
            Some(mut s) => {
                let (ct, nonce) = crypto::seal(vek.as_slice(), value, s.id.as_bytes())?;
                s.version += 1;
                self.conn.execute(
                    "UPDATE secrets SET ciphertext = ?1, nonce = ?2, type = ?3,
                                        description = ?4, updated_at = ?5, version = ?6
                     WHERE id = ?7",
                    params![
                        ct,
                        nonce.as_slice(),
                        secret_type,
                        description,
                        ts,
                        s.version,
                        s.id
                    ],
                )?;
                s.secret_type = secret_type.to_string();
                s.description = description.to_string();
                s.updated_at = ts;
                self.audit("Secret modified", &format!("{project}/{name}"), "success");
                Ok(s)
            }
        }
    }

    /// Decrypts a secret value. The caller must not persist it; use is audited.
    pub fn get_secret_value(
        &self,
        project: &str,
        env: &str,
        name: &str,
    ) -> Result<(Vec<u8>, Secret)> {
        self.require_unlocked()?;
        let environment = self.get_environment(project, env)?;
        let secret = self
            .find_secret(&environment.id, name)?
            .ok_or_else(|| Error::NotFound(format!("secret '{name}'")))?;

        let vek = self.vek.as_ref().ok_or(Error::Locked)?;
        let (ct, nonce): (Vec<u8>, Vec<u8>) = self.conn.query_row(
            "SELECT ciphertext, nonce FROM secrets WHERE id = ?1",
            params![secret.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        match crypto::open(vek.as_slice(), &ct, &nonce, secret.id.as_bytes()) {
            Ok(value) => {
                self.audit("Secret accessed", &format!("{project}/{name}"), "success");
                Ok((value, secret))
            }
            Err(e) => {
                self.audit("Secret accessed", &format!("{project}/{name}"), "failure");
                Err(e)
            }
        }
    }

    /// Lists secret metadata for an environment; values stay hidden.
    pub fn list_secrets(&self, project: &str, env: &str) -> Result<Vec<Secret>> {
        self.require_unlocked()?;
        let environment = self.get_environment(project, env)?;
        let mut stmt = self.conn.prepare(
            "SELECT id, project_id, environment_id, name, type, description,
                    created_at, updated_at, version
             FROM secrets WHERE environment_id = ?1 ORDER BY name",
        )?;
        let rows = stmt.query_map(params![environment.id], |row| {
            Ok(Secret {
                id: row.get(0)?,
                project_id: row.get(1)?,
                environment_id: row.get(2)?,
                name: row.get(3)?,
                secret_type: row.get(4)?,
                description: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
                version: row.get(8)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn delete_secret(&self, project: &str, env: &str, name: &str) -> Result<()> {
        self.require_unlocked()?;
        let environment = self.get_environment(project, env)?;
        let secret = self
            .find_secret(&environment.id, name)?
            .ok_or_else(|| Error::NotFound(format!("secret '{name}'")))?;
        self.conn
            .execute("DELETE FROM secrets WHERE id = ?1", params![secret.id])?;
        self.audit("Secret deleted", &format!("{project}/{name}"), "success");
        Ok(())
    }

    fn find_secret(&self, environment_id: &str, name: &str) -> Result<Option<Secret>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, project_id, environment_id, name, type, description,
                        created_at, updated_at, version
                 FROM secrets WHERE environment_id = ?1 AND name = ?2",
                params![environment_id, name],
                |row| {
                    Ok(Secret {
                        id: row.get(0)?,
                        project_id: row.get(1)?,
                        environment_id: row.get(2)?,
                        name: row.get(3)?,
                        secret_type: row.get(4)?,
                        description: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                        version: row.get(8)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    // --- Audit ---------------------------------------------------------------

    /// Records a security-relevant action. Never pass secret values.
    pub fn audit(&self, action: &str, resource: &str, result: &str) {
        let _ = self.conn.execute(
            "INSERT INTO audit_log (time, action, resource, result) VALUES (?1, ?2, ?3, ?4)",
            params![now(), action, resource, result],
        );
    }

    pub fn list_audit(&self, limit: i64) -> Result<Vec<AuditEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT time, action, resource, result FROM audit_log
             ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok(AuditEntry {
                time: row.get(0)?,
                action: row.get(1)?,
                resource: row.get(2)?,
                result: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    // --- Stats ---------------------------------------------------------------

    pub fn stats(&self) -> Result<Stats> {
        self.require_unlocked()?;
        let count =
            |sql: &str| -> Result<i64> { Ok(self.conn.query_row(sql, [], |row| row.get(0))?) };
        Ok(Stats {
            projects: count("SELECT COUNT(*) FROM projects")?,
            environments: count("SELECT COUNT(*) FROM environments")?,
            secrets: count("SELECT COUNT(*) FROM secrets")?,
            // SSH key management arrives in v0.3.
            ssh_keys: 0,
            unlocked: self.is_unlocked(),
        })
    }
}

pub fn config_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("ENVVAULT_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let base =
        dirs::config_dir().ok_or_else(|| Error::Invalid("cannot locate config dir".into()))?;
    Ok(base.join("envvault"))
}

fn decode_hex(s: &str, what: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|_| Error::Invalid(format!("vault meta corrupted: bad {what}")))
}

fn normalize(s: &str) -> String {
    s.trim().to_lowercase()
}
