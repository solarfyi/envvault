//! Cryptographic core of EnvVault.
//!
//! ```text
//! Master Password
//!        │
//!     Argon2id ──► Key Encryption Key (KEK)
//!        │
//! KEK ── wraps ──► Vault Encryption Key (VEK)
//! VEK ── seals ──► secret values (XChaCha20-Poly1305)
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const MIN_PASSWORD_LEN: usize = 8;

/// AAD that binds the wrapped VEK to its purpose.
pub const AAD_VEK: &[u8] = b"envvault/vek";

/// Argon2id cost parameters, stored with the vault so they can be tuned
/// later without breaking existing vaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub output_len: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 4,
            output_len: KEY_LEN,
        }
    }
}

/// Returns `n` cryptographically random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::fill(&mut buf);
    buf
}

/// Derives the key encryption key from the master password.
pub fn derive_kek(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<Zeroizing<Vec<u8>>> {
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            params.m_cost,
            params.t_cost,
            params.p_cost,
            Some(params.output_len),
        )
        .map_err(|e| Error::Invalid(format!("invalid KDF parameters: {e}")))?,
    );
    let mut out = Zeroizing::new(vec![0u8; params.output_len]);
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| Error::Invalid(format!("key derivation failed: {e}")))?;
    Ok(out)
}

/// Validates a new master password against policy.
pub fn validate_password(password: &[u8]) -> Result<()> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(Error::WeakPassword(MIN_PASSWORD_LEN));
    }
    Ok(())
}

/// Encrypts `plaintext` with XChaCha20-Poly1305 under a fresh random nonce.
/// `aad` binds the ciphertext to its context (e.g. the secret's id) so
/// records cannot be swapped without detection.
pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let key = Key::try_from(key).map_err(|_| Error::Invalid("key must be 32 bytes".into()))?;
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| Error::AuthFailed)?;
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AuthFailed)?;
    Ok((ct, nonce_bytes))
}

/// Decrypts a ciphertext produced by [`seal`].
pub fn open(key: &[u8], ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Decrypt);
    }
    let key = Key::try_from(key).map_err(|_| Error::Invalid("key must be 32 bytes".into()))?;
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = XNonce::try_from(nonce).map_err(|_| Error::Decrypt)?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = random_bytes::<KEY_LEN>();
        let (ct, nonce) = seal(&key, b"super-secret", b"id-1").unwrap();
        assert!(!ct.windows(12).any(|w| w == b"super-secret"));
        let pt = open(&key, &ct, &nonce, b"id-1").unwrap();
        assert_eq!(pt, b"super-secret");
    }

    #[test]
    fn rejects_wrong_aad() {
        let key = random_bytes::<KEY_LEN>();
        let (ct, nonce) = seal(&key, b"data", b"id-1").unwrap();
        assert!(open(&key, &ct, &nonce, b"id-2").is_err());
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = random_bytes::<KEY_LEN>();
        let (mut ct, nonce) = seal(&key, b"data", b"").unwrap();
        ct[0] ^= 0xff;
        assert!(open(&key, &ct, &nonce, b"").is_err());
    }

    #[test]
    fn kek_derivation_is_deterministic() {
        let salt = random_bytes::<SALT_LEN>();
        let params = KdfParams::default();
        let a = derive_kek(b"password123", &salt, &params).unwrap();
        let b = derive_kek(b"password123", &salt, &params).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        let c = derive_kek(b"password124", &salt, &params).unwrap();
        assert_ne!(a.as_slice(), c.as_slice());
    }

    #[test]
    fn password_policy() {
        assert!(validate_password(b"short").is_err());
        assert!(validate_password(b"longenough").is_ok());
    }
}
