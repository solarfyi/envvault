//! SQLite storage. The database contains ciphertext for every secret value;
//! only metadata (names, types, timestamps) is visible.

use std::path::Path;

use rusqlite::Connection;

use crate::error::Result;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS environments (
    id         TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, name)
);
CREATE TABLE IF NOT EXISTS secrets (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    type           TEXT NOT NULL DEFAULT 'secret',
    description    TEXT NOT NULL DEFAULT '',
    ciphertext     BLOB NOT NULL,
    nonce          BLOB NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    UNIQUE(environment_id, name)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    time     TEXT NOT NULL,
    action   TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    result   TEXT NOT NULL DEFAULT 'success'
);
CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(environment_id);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(time);
";

/// Opens the vault database with the pragmas every connection needs:
/// WAL journaling, enforced foreign keys (cascading deletes) and a busy
/// timeout so concurrent readers never race the writer.
pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
    let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(conn)
}

pub fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM meta WHERE key = ?1")?;
    let mut rows = stmt.query([key])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

pub fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )?;
    Ok(())
}
