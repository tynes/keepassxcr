use aes::{Aes128, Aes256};
use cbc::{Decryptor, Encryptor};
use chacha20::ChaCha20;
use cipher::{
    BlockCipher, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher,
    block_padding::Pkcs7,
};
use twofish::Twofish;
use uuid::Uuid;

use crate::crypto::constants::{CIPHER_AES128, CIPHER_AES256, CIPHER_CHACHA20, CIPHER_TWOFISH};
use crate::error::{AppError, AppResult};

/// Supported database ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherId {
    /// AES-128-CBC.
    Aes128,
    /// AES-256-CBC.
    Aes256,
    /// Twofish-CBC.
    Twofish,
    /// ChaCha20.
    ChaCha20,
}

impl CipherId {
    /// Map a cipher UUID to a cipher id.
    pub fn from_uuid(uuid: Uuid) -> Option<Self> {
        if uuid == CIPHER_AES128 {
            Some(Self::Aes128)
        } else if uuid == CIPHER_AES256 {
            Some(Self::Aes256)
        } else if uuid == CIPHER_TWOFISH {
            Some(Self::Twofish)
        } else if uuid == CIPHER_CHACHA20 {
            Some(Self::ChaCha20)
        } else {
            None
        }
    }

    /// Cipher UUID.
    pub fn uuid(self) -> Uuid {
        match self {
            Self::Aes128 => CIPHER_AES128,
            Self::Aes256 => CIPHER_AES256,
            Self::Twofish => CIPHER_TWOFISH,
            Self::ChaCha20 => CIPHER_CHACHA20,
        }
    }

    /// Expected key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
            Self::Twofish => 32,
            Self::ChaCha20 => 32,
        }
    }

    /// Expected IV length in bytes.
    pub fn iv_len(self) -> usize {
        match self {
            Self::ChaCha20 => 12,
            _ => 16,
        }
    }

    /// Whether this is a stream cipher.
    pub fn is_stream(self) -> bool {
        matches!(self, Self::ChaCha20)
    }
}

/// Encrypt plaintext with the selected cipher.
pub fn encrypt(cipher: CipherId, key: &[u8], iv: &[u8], plaintext: &[u8]) -> AppResult<Vec<u8>> {
    validate_key_iv(cipher, key, iv)?;
    match cipher {
        CipherId::Aes128 => encrypt_cbc::<Aes128>(key, iv, plaintext),
        CipherId::Aes256 => encrypt_cbc::<Aes256>(key, iv, plaintext),
        CipherId::Twofish => encrypt_cbc::<Twofish>(key, iv, plaintext),
        CipherId::ChaCha20 => encrypt_chacha20(key, iv, plaintext),
    }
}

/// Decrypt ciphertext with the selected cipher.
pub fn decrypt(cipher: CipherId, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> AppResult<Vec<u8>> {
    validate_key_iv(cipher, key, iv)?;
    match cipher {
        CipherId::Aes128 => decrypt_cbc::<Aes128>(key, iv, ciphertext),
        CipherId::Aes256 => decrypt_cbc::<Aes256>(key, iv, ciphertext),
        CipherId::Twofish => decrypt_cbc::<Twofish>(key, iv, ciphertext),
        CipherId::ChaCha20 => decrypt_chacha20(key, iv, ciphertext),
    }
}

fn validate_key_iv(cipher: CipherId, key: &[u8], iv: &[u8]) -> AppResult<()> {
    if key.len() != cipher.key_len() {
        return Err(AppError::Crypto(format!(
            "invalid key length {}, expected {}",
            key.len(),
            cipher.key_len()
        )));
    }
    if iv.len() != cipher.iv_len() {
        return Err(AppError::Crypto(format!(
            "invalid iv length {}, expected {}",
            iv.len(),
            cipher.iv_len()
        )));
    }
    Ok(())
}

fn encrypt_cbc<C>(key: &[u8], iv: &[u8], plaintext: &[u8]) -> AppResult<Vec<u8>>
where
    C: BlockEncryptMut + BlockCipher + KeyInit,
{
    let encryptor = Encryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| AppError::Crypto("invalid key or iv".to_string()))?;
    let mut buffer = plaintext.to_vec();
    let block_size = C::block_size();
    let pad_len = block_size - (buffer.len() % block_size);
    buffer.extend(std::iter::repeat_n(0u8, pad_len));
    encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|_| AppError::Crypto("padding error".to_string()))?;
    Ok(buffer)
}

fn decrypt_cbc<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> AppResult<Vec<u8>>
where
    C: BlockDecryptMut + BlockCipher + KeyInit,
{
    let decryptor = Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| AppError::Crypto("invalid key or iv".to_string()))?;
    let mut buffer = ciphertext.to_vec();
    let plain = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| AppError::Crypto("invalid padding".to_string()))?;
    Ok(plain.to_vec())
}

fn encrypt_chacha20(key: &[u8], iv: &[u8], plaintext: &[u8]) -> AppResult<Vec<u8>> {
    let mut cipher = ChaCha20::new_from_slices(key, iv)
        .map_err(|_| AppError::Crypto("invalid key or iv".to_string()))?;
    let mut buffer = plaintext.to_vec();
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

fn decrypt_chacha20(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> AppResult<Vec<u8>> {
    encrypt_chacha20(key, iv, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_roundtrip() {
        let key = [7u8; 32];
        let iv = [9u8; 16];
        let plaintext = b"hello world";
        let encrypted =
            encrypt(CipherId::Aes256, &key, &iv, plaintext).expect("encrypt should work");
        let decrypted =
            decrypt(CipherId::Aes256, &key, &iv, &encrypted).expect("decrypt should work");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn twofish_roundtrip() {
        let key = [3u8; 32];
        let iv = [4u8; 16];
        let plaintext = b"twofish test";
        let encrypted =
            encrypt(CipherId::Twofish, &key, &iv, plaintext).expect("encrypt should work");
        let decrypted =
            decrypt(CipherId::Twofish, &key, &iv, &encrypted).expect("decrypt should work");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha20_roundtrip() {
        let key = [1u8; 32];
        let iv = [2u8; 12];
        let plaintext = b"stream";
        let encrypted =
            encrypt(CipherId::ChaCha20, &key, &iv, plaintext).expect("encrypt should work");
        let decrypted =
            decrypt(CipherId::ChaCha20, &key, &iv, &encrypted).expect("decrypt should work");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn invalid_key_length() {
        let key = [1u8; 31];
        let iv = [2u8; 16];
        let result = encrypt(CipherId::Aes256, &key, &iv, b"data");
        assert!(result.is_err());
    }
}
