use argon2::{Algorithm, Argon2, Block, Params, Version};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::constants::{KDF_AES_KDBX3, KDF_AES_KDBX4, KDF_ARGON2D, KDF_ARGON2ID};
use crate::crypto::hash::sha256;
use crate::error::{AppError, AppResult};

/// A progress callback for key derivation: `hook(done, total)`.
pub type KdfProgressHook = dyn Fn(u64, u64) + Send + Sync;

static PROGRESS_HOOK: RwLock<Option<Arc<KdfProgressHook>>> = RwLock::new(None);

/// Report the progress of every [`KdfConfig::transform`] in this process to `hook`.
///
/// The library never writes to the terminal itself. The `keepassxcr` CLI uses
/// this to draw a progress bar during long AES-KDF runs, which happen deep
/// inside [`crate::format::read_kdbx`] and [`crate::format::write_kdbx`].
/// Pass `None` to remove the hook. See [`KdfConfig::transform_with_progress`]
/// for when it is called.
pub fn set_kdf_progress_hook(hook: Option<Arc<KdfProgressHook>>) {
    if let Ok(mut slot) = PROGRESS_HOOK.write() {
        *slot = hook;
    }
}

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
    ///
    /// Reports progress to the hook set with [`set_kdf_progress_hook`], if any.
    pub fn transform(&self, raw_key: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
        let hook = PROGRESS_HOOK.read().ok().and_then(|hook| hook.clone());
        match hook {
            Some(hook) => {
                self.transform_with_progress(raw_key, &mut |done, total| hook(done, total))
            }
            None => self.transform_with_progress(raw_key, &mut |_, _| {}),
        }
    }

    /// Transform a raw composite key, calling `progress(done, total)` as it runs.
    ///
    /// AES-KDF reports `(0, rounds)` before the first round, then about a
    /// thousand updates, and `(rounds, rounds)` when done. Argon2 runs as one
    /// step and reports nothing. The result is wiped when dropped.
    pub fn transform_with_progress(
        &self,
        raw_key: &[u8],
        progress: &mut dyn FnMut(u64, u64),
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        match self {
            Self::Aes { seed, rounds, .. } => aes_kdf(seed, *rounds, raw_key, progress),
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

fn aes_kdf(
    seed: &[u8],
    rounds: u64,
    raw_key: &[u8],
    progress: &mut dyn FnMut(u64, u64),
) -> AppResult<Zeroizing<Vec<u8>>> {
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

    let chunk = (rounds / 1000).max(1);
    progress(0, rounds);
    for round in 1..=rounds {
        cipher.encrypt_block(&mut block1);
        cipher.encrypt_block(&mut block2);
        if round.is_multiple_of(chunk) && round != rounds {
            progress(round, rounds);
        }
    }
    progress(rounds, rounds);

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
    // The memory size comes from the file. Refuse more than the machine has and
    // allocate fallibly, so an impossible value is an error instead of an abort.
    // The first check matters on macOS, where a huge reservation succeeds and the
    // process is killed once the memory is touched.
    let cannot_allocate = || {
        AppError::Crypto(format!(
            "cannot allocate {} MiB for Argon2",
            memory_kib / 1024
        ))
    };
    if physical_memory().is_some_and(|total| u64::from(memory_kib) * 1024 > total) {
        return Err(cannot_allocate());
    }
    let block_count = params.block_count();
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| cannot_allocate())?;
    blocks.resize(block_count, Block::default());
    let argon2 = Argon2::new(alg, ver, params);

    let mut output = Zeroizing::new(vec![0u8; 32]);
    let result = argon2.hash_password_into_with_memory(raw_key, salt, &mut output, &mut blocks);
    // The working memory is derived from the key.
    blocks.zeroize();
    result.map_err(|err| AppError::Crypto(format!("argon2 failed: {err}")))?;
    Ok(output)
}

/// Total physical memory in bytes, when the OS reports it.
#[cfg(unix)]
fn physical_memory() -> Option<u64> {
    // SAFETY: sysconf only reads system configuration values.
    let (pages, page_size) = unsafe {
        (
            libc::sysconf(libc::_SC_PHYS_PAGES),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    let pages = u64::try_from(pages).ok()?;
    let page_size = u64::try_from(page_size).ok()?;
    pages.checked_mul(page_size)
}

#[cfg(not(unix))]
fn physical_memory() -> Option<u64> {
    None
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
    fn aes_kdf_reports_progress_and_same_key() {
        let kdf = KdfConfig::Aes {
            seed: vec![7u8; 32],
            rounds: 5_000,
            legacy: false,
        };
        let raw_key = vec![1u8; 32];
        let mut calls = Vec::new();
        let out = kdf
            .transform_with_progress(&raw_key, &mut |done, total| calls.push((done, total)))
            .expect("kdf should run");
        assert_eq!(calls.first(), Some(&(0, 5_000)));
        assert_eq!(calls.last(), Some(&(5_000, 5_000)));
        assert!(calls.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(calls.len(), 1_001);
        assert_eq!(
            &out[..],
            &kdf.transform(&raw_key).expect("kdf should run")[..]
        );
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
