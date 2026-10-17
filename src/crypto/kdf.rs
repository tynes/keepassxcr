use argon2::{Algorithm, Argon2, Block, Params, Version};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::constants::{KDF_AES_KDBX3, KDF_AES_KDBX4, KDF_ARGON2D, KDF_ARGON2ID};
use crate::crypto::hash::sha256;
use crate::error::{AppError, AppResult};

/// Supported KDF types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfType {
    /// AES-KDF for KDBX3 compatibility.
    AesKdbx3,
    /// AES-KDF for KDBX4.
    AesKdbx4,
    /// Argon2d.
    Argon2d,
    /// Argon2id.
    Argon2id,
}

impl KdfType {
    /// UUID for this KDF type.
    pub fn uuid(self) -> Uuid {
        match self {
            Self::AesKdbx3 => KDF_AES_KDBX3,
            Self::AesKdbx4 => KDF_AES_KDBX4,
            Self::Argon2d => KDF_ARGON2D,
            Self::Argon2id => KDF_ARGON2ID,
        }
    }

    /// Resolve from UUID.
    pub fn from_uuid(uuid: Uuid) -> Option<Self> {
        if uuid == KDF_AES_KDBX3 {
            Some(Self::AesKdbx3)
        } else if uuid == KDF_AES_KDBX4 {
            Some(Self::AesKdbx4)
        } else if uuid == KDF_ARGON2D {
            Some(Self::Argon2d)
        } else if uuid == KDF_ARGON2ID {
            Some(Self::Argon2id)
        } else {
            None
        }
    }
}

/// Key derivation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KdfConfig {
    /// AES-KDF configuration.
    Aes {
        /// Seed for AES-KDF.
        seed: Vec<u8>,
        /// Rounds for AES-KDF.
        rounds: u64,
        /// Compatibility flag for KDBX3.
        legacy: bool,
    },
    /// Argon2 configuration.
    Argon2 {
        /// Argon2 type.
        kind: KdfType,
        /// Salt bytes.
        salt: Vec<u8>,
        /// Iterations.
        iterations: u32,
        /// Memory in KiB.
        memory_kib: u32,
        /// Parallelism.
        parallelism: u32,
        /// Argon2 version.
        version: u32,
    },
}

impl KdfConfig {
    /// Return the KDF UUID.
    pub fn uuid(&self) -> Uuid {
        match self {
            Self::Aes { legacy, .. } => {
                if *legacy {
                    KdfType::AesKdbx3.uuid()
                } else {
                    KdfType::AesKdbx4.uuid()
                }
            }
            Self::Argon2 { kind, .. } => kind.uuid(),
        }
    }

    /// Return the KDF seed/salt.
    pub fn seed(&self) -> &[u8] {
        match self {
            Self::Aes { seed, .. } => seed,
            Self::Argon2 { salt, .. } => salt,
        }
    }

    /// Transform a raw composite key. The result is wiped when dropped.
    pub fn transform(&self, raw_key: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        match self {
            Self::Aes { seed, rounds, .. } => aes_kdf(seed, *rounds, raw_key),
            Self::Argon2 {
                kind,
                salt,
                iterations,
                memory_kib,
                parallelism,
                version,
            } => argon2_kdf(
                *kind,
                salt,
                *iterations,
                *memory_kib,
                *parallelism,
                *version,
                raw_key,
            ),
        }
    }

    /// Build a default Argon2id configuration.
    pub fn default_argon2id() -> Self {
        Self::Argon2 {
            kind: KdfType::Argon2id,
            salt: vec![0u8; 32],
            iterations: 3,
            memory_kib: 64 * 1024,
            parallelism: 2,
            version: 0x13,
        }
    }

    /// Build a default AES-KDF configuration.
    pub fn default_aes(legacy: bool) -> Self {
        Self::Aes {
            seed: vec![0u8; 32],
            rounds: 100_000,
            legacy,
        }
    }
}

fn aes_kdf(seed: &[u8], rounds: u64, raw_key: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
    use aes::Aes256;
    use cipher::generic_array::GenericArray;
    use cipher::{BlockEncrypt, KeyInit};

    if seed.len() != 32 {
        return Err(AppError::Crypto(
            "AES-KDF seed must be 32 bytes".to_string(),
        ));
    }
    if raw_key.len() != 32 {
        return Err(AppError::Crypto(
            "AES-KDF raw key must be 32 bytes".to_string(),
        ));
    }

    let cipher = Aes256::new_from_slice(seed)
        .map_err(|_| AppError::Crypto("invalid AES-KDF seed".to_string()))?;

    let mut block1 = GenericArray::clone_from_slice(&raw_key[..16]);
    let mut block2 = GenericArray::clone_from_slice(&raw_key[16..]);

    let progress = if rounds >= 50_000 {
        let pb = ProgressBar::new(rounds);
        pb.set_style(
            ProgressStyle::with_template("{msg} {wide_bar} {pos}/{len}")
                .map_err(|_| AppError::Crypto("progress style".to_string()))?,
        );
        pb.set_message("AES-KDF");
        Some(pb)
    } else {
        None
    };

    let chunk = (rounds / 1000).max(1);
    let mut completed = 0u64;

    for _ in 0..rounds {
        cipher.encrypt_block(&mut block1);
        cipher.encrypt_block(&mut block2);
        if let Some(pb) = &progress {
            completed += 1;
            if completed % chunk == 0 {
                pb.inc(chunk);
            }
        }
    }

    if let Some(pb) = progress {
        let remaining = rounds.saturating_sub(pb.position());
        if remaining > 0 {
            pb.inc(remaining);
        }
        pb.finish_and_clear();
    }

    let mut transformed = Zeroizing::new([0u8; 32]);
    transformed[..16].copy_from_slice(&block1);
    transformed[16..].copy_from_slice(&block2);
    block1.as_mut_slice().zeroize();
    block2.as_mut_slice().zeroize();
    Ok(Zeroizing::new(sha256(&transformed[..]).to_vec()))
}

fn argon2_kdf(
    kind: KdfType,
    salt: &[u8],
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
    version: u32,
    raw_key: &[u8],
) -> AppResult<Zeroizing<Vec<u8>>> {
    let alg = match kind {
        KdfType::Argon2d => Algorithm::Argon2d,
        KdfType::Argon2id => Algorithm::Argon2id,
        _ => {
            return Err(AppError::Crypto("invalid Argon2 KDF type".to_string()));
        }
    };

    let ver = match version {
        0x10 => Version::V0x10,
        0x13 => Version::V0x13,
        _ => return Err(AppError::Crypto("unsupported Argon2 version".to_string())),
    };

    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|err| AppError::Crypto(format!("invalid Argon2 params: {err}")))?;
    // The memory size comes from the file. Allocate it fallibly so an
    // impossible value is an error instead of an abort.
    let block_count = params.block_count();
    let mut blocks = Vec::new();
    blocks.try_reserve_exact(block_count).map_err(|_| {
        AppError::Crypto(format!(
            "cannot allocate {} MiB for Argon2",
            memory_kib / 1024
        ))
    })?;
    blocks.resize(block_count, Block::default());
    let argon2 = Argon2::new(alg, ver, params);

    let mut output = Zeroizing::new(vec![0u8; 32]);
    let result = argon2.hash_password_into_with_memory(raw_key, salt, &mut output, &mut blocks);
    // The working memory is derived from the key.
    blocks.zeroize();
    result.map_err(|err| AppError::Crypto(format!("argon2 failed: {err}")))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_uuid_roundtrip() {
        let kdf = KdfConfig::default_aes(true);
        assert_eq!(kdf.uuid(), KDF_AES_KDBX3);
        let kdf = KdfConfig::default_aes(false);
        assert_eq!(kdf.uuid(), KDF_AES_KDBX4);
    }

    #[test]
    fn aes_kdf_transform_length() {
        let kdf = KdfConfig::Aes {
            seed: vec![7u8; 32],
            rounds: 10,
            legacy: true,
        };
        let raw_key = vec![1u8; 32];
        let out = kdf.transform(&raw_key).expect("kdf should run");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn argon2_transform_length() {
        let kdf = KdfConfig::Argon2 {
            kind: KdfType::Argon2id,
            salt: vec![2u8; 32],
            iterations: 2,
            memory_kib: 32,
            parallelism: 1,
            version: 0x13,
        };
        let raw_key = vec![3u8; 32];
        let out = kdf.transform(&raw_key).expect("argon2 should run");
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn impossible_argon2_memory_is_an_error() {
        let kdf = KdfConfig::Argon2 {
            kind: KdfType::Argon2id,
            salt: vec![2u8; 32],
            iterations: 1,
            memory_kib: u32::MAX,
            parallelism: 1,
            version: 0x13,
        };
        let err = kdf
            .transform(&[3u8; 32])
            .expect_err("4 TiB cannot be allocated");
        assert!(err.to_string().contains("cannot allocate"), "{err}");
    }
}
