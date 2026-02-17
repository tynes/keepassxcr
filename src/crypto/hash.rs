use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{AppError, AppResult};

/// Compute a SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Compute a SHA-512 digest.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Compute HMAC-SHA256 for the given data.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> AppResult<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|err| AppError::Crypto(format!("invalid HMAC key: {err}")))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Derive the KDBX4 HMAC base key.
pub fn kdbx_hmac_key(master_seed: &[u8], transformed_key: &[u8]) -> [u8; 64] {
    let mut buf = Vec::with_capacity(master_seed.len() + transformed_key.len() + 1);
    buf.extend_from_slice(master_seed);
    buf.extend_from_slice(transformed_key);
    buf.push(0x01);
    sha512(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_value() {
        let digest = sha256(b"abc");
        let expected = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
            0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
            0xF2, 0x00, 0x15, 0xAD,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha512_length() {
        let digest = sha512(b"abc");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn hmac_sha256_roundtrip() {
        let mac = hmac_sha256(b"key", b"data").expect("hmac should succeed");
        assert_eq!(mac.len(), 32);
    }

    #[test]
    fn hmac_key_length() {
        let key = kdbx_hmac_key(&[1, 2, 3], &[4, 5, 6]);
        assert_eq!(key.len(), 64);
    }
}
