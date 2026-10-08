use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("vault already exists at {0}")]
    VaultExists(String),

    #[error("vault not found — run 'envvault init'")]
    VaultNotFound,

    #[error("vault is locked — run 'envvault unlock'")]
    Locked,

    #[error("incorrect master password")]
    WrongPassword,

    #[error("no active session — run 'envvault unlock'")]
    NoSession,

    #[error("session expired — run 'envvault unlock'")]
    SessionExpired,

    #[error("'{0}' already exists")]
    AlreadyExists(String),

    #[error("'{0}' not found")]
    NotFound(String),

    #[error("master password must be at least {0} characters")]
    WeakPassword(usize),

    #[error("decryption failed: wrong master password or corrupted data")]
    Decrypt,

    #[error("ciphertext failed authentication")]
    AuthFailed,

    #[error("{0}")]
    Invalid(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}
