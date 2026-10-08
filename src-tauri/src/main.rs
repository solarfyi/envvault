//! EnvVault desktop application.
//!
//! Thin Tauri layer over the same core library the CLI uses: every command
//! below just forwards to `envvault::vault::Vault`.

use std::path::PathBuf;
use std::sync::Mutex;

use envvault::error::Error;
use envvault::session;
use envvault::vault::{AuditEntry, Environment, Project, Secret, Stats, Vault};
use tauri::State;

struct AppState(Mutex<Option<Vault>>);

type CmdResult<T> = Result<T, String>;

fn wrap<T>(result: envvault::error::Result<T>) -> CmdResult<T> {
    result.map_err(|e| e.to_string())
}

fn vault_path() -> PathBuf {
    if let Ok(p) = std::env::var("ENVVAULT_VAULT") {
        return PathBuf::from(p);
    }
    Vault::default_path().unwrap_or_else(|_| PathBuf::from("vault.db"))
}

/// Runs an operation against the unlocked vault.
fn with_vault<T>(
    state: &AppState,
    f: impl FnOnce(&Vault) -> envvault::error::Result<T>,
) -> CmdResult<T> {
    let guard = state
        .0
        .lock()
        .map_err(|_| "internal state error".to_string())?;
    match guard.as_ref() {
        Some(vault) => wrap(f(vault)),
        None => Err(Error::Locked.to_string()),
    }
}

#[derive(serde::Serialize)]
struct UiStatus {
    exists: bool,
    unlocked: bool,
    vault_path: String,
    stats: Option<Stats>,
}

#[tauri::command]
fn status(state: State<AppState>) -> CmdResult<UiStatus> {
    let path = vault_path();
    let exists = Vault::exists(&path);
    let guard = state
        .0
        .lock()
        .map_err(|_| "internal state error".to_string())?;
    let stats = match guard.as_ref() {
        Some(vault) => Some(wrap(vault.stats())?),
        None => None,
    };
    Ok(UiStatus {
        exists,
        unlocked: guard.is_some(),
        vault_path: path.display().to_string(),
        stats,
    })
}

#[tauri::command]
fn init(state: State<AppState>, password: String) -> CmdResult<()> {
    let path = vault_path();
    if Vault::exists(&path) {
        return Err(Error::VaultExists(path.display().to_string()).to_string());
    }
    let vault = wrap(Vault::create(&path, password.as_bytes()))?;
    wrap(vault.save_session())?;
    *state
        .0
        .lock()
        .map_err(|_| "internal state error".to_string())? = Some(vault);
    Ok(())
}

#[tauri::command]
fn unlock(state: State<AppState>, password: String) -> CmdResult<()> {
    let path = vault_path();
    let vault = wrap(Vault::open(&path, password.as_bytes()))?;
    wrap(vault.save_session())?;
    *state
        .0
        .lock()
        .map_err(|_| "internal state error".to_string())? = Some(vault);
    Ok(())
}

#[tauri::command]
fn lock(state: State<AppState>) -> CmdResult<()> {
    let mut guard = state
        .0
        .lock()
        .map_err(|_| "internal state error".to_string())?;
    if let Some(vault) = guard.as_mut() {
        vault.lock();
    }
    *guard = None;
    wrap(session::clear())
}

#[tauri::command]
fn list_projects(state: State<AppState>) -> CmdResult<Vec<Project>> {
    with_vault(&state, |v| v.list_projects())
}

#[tauri::command]
fn create_project(state: State<AppState>, name: String, description: String) -> CmdResult<Project> {
    with_vault(&state, |v| v.create_project(&name, &description))
}

#[tauri::command]
fn delete_project(state: State<AppState>, name: String) -> CmdResult<()> {
    with_vault(&state, |v| v.delete_project(&name))
}

#[tauri::command]
fn list_environments(state: State<AppState>, project: String) -> CmdResult<Vec<Environment>> {
    with_vault(&state, |v| v.list_environments(&project))
}

#[tauri::command]
fn create_environment(
    state: State<AppState>,
    project: String,
    name: String,
) -> CmdResult<Environment> {
    with_vault(&state, |v| v.create_environment(&project, &name))
}

#[tauri::command]
fn list_secrets(state: State<AppState>, project: String, env: String) -> CmdResult<Vec<Secret>> {
    with_vault(&state, |v| v.list_secrets(&project, &env))
}

#[tauri::command]
fn set_secret(
    state: State<AppState>,
    project: String,
    env: String,
    name: String,
    secret_type: String,
    description: String,
    value: String,
) -> CmdResult<Secret> {
    with_vault(&state, |v| {
        v.set_secret(
            &project,
            &env,
            &name,
            &secret_type,
            &description,
            value.as_bytes(),
        )
    })
}

/// Decrypts a single secret. Explicit user action; audited by the core.
#[tauri::command]
fn reveal_secret(
    state: State<AppState>,
    project: String,
    env: String,
    name: String,
) -> CmdResult<String> {
    with_vault(&state, |v| {
        let (value, _) = v.get_secret_value(&project, &env, &name)?;
        Ok(String::from_utf8_lossy(&value).into_owned())
    })
}

#[tauri::command]
fn delete_secret(
    state: State<AppState>,
    project: String,
    env: String,
    name: String,
) -> CmdResult<()> {
    with_vault(&state, |v| v.delete_secret(&project, &env, &name))
}

#[tauri::command]
fn list_audit(state: State<AppState>, limit: Option<i64>) -> CmdResult<Vec<AuditEntry>> {
    with_vault(&state, |v| v.list_audit(limit.unwrap_or(100)))
}

fn main() {
    tauri::Builder::default()
        .manage(AppState(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            status,
            init,
            unlock,
            lock,
            list_projects,
            create_project,
            delete_project,
            list_environments,
            create_environment,
            list_secrets,
            set_secret,
            reveal_secret,
            delete_secret,
            list_audit
        ])
        .run(tauri::generate_context!())
        .expect("error while running EnvVault");
}
