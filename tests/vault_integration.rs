use std::sync::Mutex;

use envvault::error::Error;
use envvault::session;
use envvault::vault::Vault;

const PASSWORD: &[u8] = b"test-password-1";

/// Guards tests that mutate process-wide environment variables.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_vault_path() -> std::path::PathBuf {
    tempfile::tempdir()
        .expect("temp dir")
        .keep()
        .join("vault.db")
}

#[test]
fn create_rejects_wrong_password() {
    let path = temp_vault_path();
    Vault::create(&path, PASSWORD).expect("create");

    match Vault::open(&path, b"wrong-password").err() {
        Some(Error::WrongPassword) => {}
        other => panic!("expected WrongPassword, got {other:?}"),
    }
    Vault::open(&path, PASSWORD).expect("correct password opens vault");
}

#[test]
fn create_twice_fails() {
    let path = temp_vault_path();
    Vault::create(&path, PASSWORD).expect("create");
    assert!(matches!(
        Vault::create(&path, PASSWORD),
        Err(Error::VaultExists(_))
    ));
}

#[test]
fn weak_password_rejected() {
    let path = temp_vault_path();
    assert!(matches!(
        Vault::create(&path, b"short"),
        Err(Error::WeakPassword(_))
    ));
    assert!(!path.exists());
}

#[test]
fn secret_lifecycle() {
    let path = temp_vault_path();
    let vault = Vault::create(&path, PASSWORD).expect("create");

    vault.create_project("Buddy", "demo").expect("project");
    vault
        .create_environment("buddy", "development")
        .expect("env");

    let s = vault
        .set_secret(
            "buddy",
            "development",
            "API_KEY",
            "api-key",
            "test",
            b"sk-12345",
        )
        .expect("set");
    assert_eq!(s.version, 1);

    let s = vault
        .set_secret(
            "buddy",
            "development",
            "API_KEY",
            "api-key",
            "test",
            b"sk-67890",
        )
        .expect("update");
    assert_eq!(s.version, 2);

    let (value, meta) = vault
        .get_secret_value("buddy", "development", "API_KEY")
        .expect("get");
    assert_eq!(value, b"sk-67890");
    assert_eq!(meta.secret_type, "api-key");

    let list = vault.list_secrets("buddy", "development").expect("list");
    assert_eq!(list.len(), 1);

    vault
        .delete_secret("buddy", "development", "API_KEY")
        .expect("delete");
    assert!(matches!(
        vault.get_secret_value("buddy", "development", "API_KEY"),
        Err(Error::NotFound(_))
    ));
}

#[test]
fn values_are_ciphertext_at_rest() {
    let path = temp_vault_path();
    {
        let mut vault = Vault::create(&path, PASSWORD).expect("create");
        vault.create_project("p", "").expect("project");
        vault.create_environment("p", "development").expect("env");
        vault
            .set_secret(
                "p",
                "development",
                "DB_URL",
                "database",
                "",
                b"postgres://user:hunter2@db/prod",
            )
            .expect("set");
        vault.lock();
    }

    // Scan every file next to the vault, including WAL/SHM sidecars.
    let dir = path.parent().expect("parent");
    let mut raw = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("entry");
        raw.extend(std::fs::read(entry.path()).unwrap_or_default());
    }
    assert!(
        !raw.windows(7).any(|w| w == b"hunter2"),
        "plaintext secret found on disk"
    );
}

#[test]
fn delete_project_cascades() {
    let path = temp_vault_path();
    let vault = Vault::create(&path, PASSWORD).expect("create");
    vault.create_project("p", "").expect("project");
    vault.create_environment("p", "development").expect("env");
    vault
        .set_secret("p", "development", "KEY", "secret", "", b"value")
        .expect("set");

    vault.delete_project("p").expect("delete");
    let stats = vault.stats().expect("stats");
    assert_eq!(stats.projects, 0);
    assert_eq!(stats.environments, 0);
    assert_eq!(stats.secrets, 0);
}

#[test]
fn audit_log_never_contains_values() {
    let path = temp_vault_path();
    let vault = Vault::create(&path, PASSWORD).expect("create");
    vault.create_project("buddy", "").expect("project");
    vault
        .create_environment("buddy", "development")
        .expect("env");
    vault
        .set_secret(
            "buddy",
            "development",
            "API_KEY",
            "api-key",
            "",
            b"sk-secret-value",
        )
        .expect("set");
    vault
        .get_secret_value("buddy", "development", "API_KEY")
        .expect("get");

    let entries = vault.list_audit(100).expect("audit");
    assert!(!entries.is_empty());
    for e in entries {
        let blob = format!("{}{}{}", e.action, e.resource, e.result);
        assert!(
            !blob.contains("sk-secret-value"),
            "audit leaks value: {e:?}"
        );
    }
}

#[test]
fn locked_vault_rejects_access() {
    let path = temp_vault_path();
    let mut vault = Vault::create(&path, PASSWORD).expect("create");
    vault.lock();
    assert!(matches!(vault.list_projects(), Err(Error::Locked)));
}

#[test]
fn session_round_trip() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let config = tempfile::tempdir().expect("config dir");
    unsafe { std::env::set_var("ENVVAULT_CONFIG_DIR", config.path()) };

    let path = temp_vault_path();
    {
        let vault = Vault::create(&path, PASSWORD).expect("create");
        vault.create_project("p", "").expect("project");
        vault.save_session().expect("save session");
    }

    let restored = session::load(Some(&path)).expect("load session");
    assert_eq!(restored.list_projects().expect("projects").len(), 1);
    drop(restored);

    session::clear().expect("clear");
    assert!(matches!(session::load(Some(&path)), Err(Error::NoSession)));

    unsafe { std::env::remove_var("ENVVAULT_CONFIG_DIR") };
}

#[test]
fn session_expiry_locks_vault() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let config = tempfile::tempdir().expect("config dir");
    unsafe { std::env::set_var("ENVVAULT_CONFIG_DIR", config.path()) };

    let path = temp_vault_path();
    {
        let vault = Vault::create(&path, PASSWORD).expect("create");
        vault.save_session().expect("save session");
    }

    // Force the deadline into the past.
    let session_file = config.path().join("session.json");
    let data = std::fs::read_to_string(&session_file).expect("session file");
    let mut json: serde_json::Value = serde_json::from_str(&data).expect("session json");
    json["deadline"] = serde_json::Value::String("2000-01-01T00:00:00+00:00".into());
    std::fs::write(&session_file, serde_json::to_vec(&json).expect("serialize")).expect("rewrite");

    assert!(matches!(
        session::load(Some(&path)),
        Err(Error::SessionExpired)
    ));
    assert!(matches!(session::load(Some(&path)), Err(Error::NoSession)));

    unsafe { std::env::remove_var("ENVVAULT_CONFIG_DIR") };
}

#[test]
fn session_bound_to_vault_path() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let config = tempfile::tempdir().expect("config dir");
    unsafe { std::env::set_var("ENVVAULT_CONFIG_DIR", config.path()) };

    let path = temp_vault_path();
    {
        let vault = Vault::create(&path, PASSWORD).expect("create");
        vault.save_session().expect("save session");
    }
    let other = config.path().join("other.db");
    assert!(matches!(session::load(Some(&other)), Err(Error::NoSession)));

    unsafe { std::env::remove_var("ENVVAULT_CONFIG_DIR") };
}
