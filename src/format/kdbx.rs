use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::agent::AgentKey;
use crate::crypto::{
    CipherId, CompositeKey, KdfConfig, KdfType, KeyFile, ProtectedStreamAlgo, decrypt, encrypt,
    hmac_sha256, kdbx_hmac_key, sha256,
};
use crate::error::{AppError, AppResult};
use crate::format::block_stream::{
    decode_hashed_blocks, decode_hmac_blocks, encode_hashed_blocks, encode_hmac_blocks,
    hmac_block_key,
};
use crate::format::constants::{
    FILE_VERSION_3_1, HeaderFieldId, InnerHeaderFieldId, KDBX_SIGNATURE_1, KDBX_SIGNATURE_2,
};
use crate::format::types::{Compression, KdbxVersion};
use crate::format::variant_map::{VariantValue, read_variant_map, write_variant_map};
use crate::model::Database;
use crate::util::{read_u16_le, read_u32_le, read_u64_le, read_vec, write_u16_le, write_u32_le};
use crate::xml::{BinaryPool, PoolBinary, read_database, requires_kdbx41, write_database};
use crate::yubikey::{self, YubiKeySlot};

/// Credentials for database operations.
#[derive(Clone)]
pub struct Credentials {
    /// Optional password.
    pub password: Option<SecretString>,
    /// Optional key file.
    pub key_file: Option<KeyFile>,
    /// Optional YubiKey challenge-response slot.
    pub yubikey: Option<YubiKeySlot>,
    /// Unlocked agent holding the composite key, used instead of the fields above.
    pub agent: Option<AgentKey>,
}

impl std::fmt::Debug for Credentials {
    /// Shows which credentials are present, never their values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("password", &self.password.is_some())
            .field("key_file", &self.key_file.is_some())
            .field("yubikey", &self.yubikey)
            .field("agent", &self.agent)
            .finish()
    }
}

impl Credentials {
    /// Build a composite key from the password and key file.
    pub fn composite_key(&self) -> AppResult<CompositeKey> {
        let mut composite = CompositeKey::new();
        if let Some(password) = &self.password {
            composite.add_password(password);
        }
        if let Some(key_file) = &self.key_file {
            composite.add_keyfile(key_file);
        }
        Ok(composite)
    }

    /// True if no credential components were provided.
    pub fn is_empty(&self) -> bool {
        self.password.is_none()
            && self.key_file.is_none()
            && self.yubikey.is_none()
            && self.agent.is_none()
    }

    /// SHA-256 of the YubiKey's answer to `challenge`, or `None` without a
    /// YubiKey. This is what KeePassXC's `CompositeKey::challenge` returns.
    ///
    /// With the unlock agent, a result the agent remembers is used without
    /// asking the YubiKey.
    ///
    /// # Errors
    ///
    /// Fails when the YubiKey cannot be reached or does not answer.
    fn challenge_response(&self, challenge: &[u8]) -> AppResult<Option<ChallengeResponse>> {
        let slot = match &self.agent {
            Some(agent) => {
                if let Some(response) = agent.recall(challenge)? {
                    return Ok(Some(ChallengeResponse {
                        response,
                        fresh: false,
                    }));
                }
                agent.yubikey()
            }
            None => self.yubikey,
        };
        slot.map(|slot| {
            Ok(ChallengeResponse {
                response: sha256(&yubikey::challenge(slot, challenge)?[..]),
                fresh: true,
            })
        })
        .transpose()
    }

    /// Tell the unlock agent a YubiKey result that just worked.
    fn keep(&self, keys: &DerivedKeys) -> AppResult<()> {
        if let (Some(agent), Some(response)) = (&self.agent, &keys.challenge_response)
            && response.fresh
        {
            agent.remember(&keys.challenge, &response.response)?;
        }
        Ok(())
    }

    /// Run the KDF over the composite key, locally or in the unlock agent.
    ///
    /// `challenge_response` is appended to the key components first (KDBX 4).
    /// The result is wiped when dropped.
    pub fn transform_key(
        &self,
        kdf: &KdfConfig,
        challenge_response: Option<&[u8; 32]>,
    ) -> AppResult<Zeroizing<Vec<u8>>> {
        if let Some(agent) = &self.agent {
            return agent.transform(kdf, challenge_response);
        }
        let composite = self.composite_key()?;
        // A YubiKey alone is a valid key. In KDBX 3.1 its answer goes into the
        // final key, so the KDF then runs over the hash of nothing, as upstream.
        if composite.is_empty() && self.yubikey.is_none() {
            return Err(AppError::InvalidInput("empty composite key".to_string()));
        }
        kdf.transform(&composite.raw_key_with(challenge_response))
    }

    /// Derive the KDF output and final key for a file with these seeds.
    ///
    /// KeePassXC challenges the YubiKey with the KDF seed in KDBX 4 and mixes
    /// the answer in before the KDF, but with the master seed in KDBX 3.1 and
    /// mixes it into the final key (`Kdbx3Reader.cpp`, `CompositeKey.cpp`).
    fn derive_keys(
        &self,
        version: KdbxVersion,
        kdf: &KdfConfig,
        master_seed: &[u8],
    ) -> AppResult<DerivedKeys> {
        let kdbx4 = version.is_kdbx4();
        let challenge = if kdbx4 { kdf.seed() } else { master_seed };
        let challenge_response = self.challenge_response(challenge)?;
        let response = challenge_response.as_ref().map(|result| &result.response);
        let (before_kdf, in_final_key) = if kdbx4 {
            (response, None)
        } else {
            (None, response)
        };
        let transformed = self.transform_key(kdf, before_kdf)?;
        let final_key = build_final_key(master_seed, in_final_key, &transformed);
        Ok(DerivedKeys {
            transformed,
            final_key,
            challenge: challenge.to_vec(),
            challenge_response,
        })
    }
}

/// A YubiKey result, and whether the YubiKey was just asked for it.
struct ChallengeResponse {
    response: [u8; 32],
    fresh: bool,
}

struct DerivedKeys {
    transformed: Zeroizing<Vec<u8>>,
    final_key: Zeroizing<[u8; 32]>,
    challenge: Vec<u8>,
    challenge_response: Option<ChallengeResponse>,
}

/// Parsed KDBX file with settings and data.
#[derive(Debug, Clone)]
pub struct KdbxFile {
    /// KDBX version. Saving keeps it, except that a 4.0 file is written as
    /// 4.1 when the database uses a 4.1 feature.
    pub version: KdbxVersion,
    /// KDBX4 `PublicCustomData` header field: an unencrypted variant map
    /// that plugins use. Kept byte for byte.
    pub public_custom_data: Option<Vec<u8>>,
    /// Database cipher.
    pub cipher: CipherId,
    /// Compression settings.
    pub compression: Compression,
    /// Key derivation configuration.
    pub kdf: KdfConfig,
    /// Protected stream algorithm.
    pub protected_stream: ProtectedStreamAlgo,
    /// Database content.
    pub database: Database,
}

/// Read a KDBX database from disk.
pub fn read_kdbx(path: &Path, credentials: &Credentials) -> AppResult<KdbxFile> {
    let data = fs::read(path)?;
    read_kdbx_bytes(&data, credentials)
}

/// Write a KDBX database to disk.
///
/// The file is replaced atomically: the data is written and flushed to a
/// temporary file in the same directory, which is then renamed over the
/// database. A crash or full disk mid-save leaves the previous file intact.
pub fn write_kdbx(path: &Path, file: &KdbxFile, credentials: &Credentials) -> AppResult<()> {
    let data = write_kdbx_bytes(file, credentials)?;
    write_atomic(path, &data)
}

/// Atomically replace `path` with `data`, keeping the existing file's permissions.
fn write_atomic(path: &Path, data: &[u8]) -> AppResult<()> {
    // Follow a symlinked database so the link itself is not replaced by a file.
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let file_name = target
        .file_name()
        .ok_or_else(|| AppError::InvalidInput("database path has no file name".to_string()))?;
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let temp = dir.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        hex::encode(suffix)
    ));

    let result = (|| -> AppResult<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // New databases are private to the user by default.
            options.mode(0o600);
        }
        let mut handle = options.open(&temp)?;
        if let Ok(existing) = fs::metadata(&target) {
            handle.set_permissions(existing.permissions())?;
        }
        handle.write_all(data)?;
        handle.sync_all()?;
        drop(handle);
        fs::rename(&temp, &target)?;
        #[cfg(unix)]
        if let Ok(directory) = fs::File::open(&dir) {
            // Persist the rename itself; failure here does not lose data.
            let _ = directory.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_kdbx_bytes(data: &[u8], credentials: &Credentials) -> AppResult<KdbxFile> {
    let mut cursor = Cursor::new(data);

    let sig1 = read_u32_le(&mut cursor)?;
    let sig2 = read_u32_le(&mut cursor)?;
    if sig1 != KDBX_SIGNATURE_1 || sig2 != KDBX_SIGNATURE_2 {
        return Err(AppError::Format("invalid KDBX signature".to_string()));
    }

    let version_raw = read_u32_le(&mut cursor)?;
    let version = KdbxVersion::from_u32(version_raw)
        .ok_or_else(|| AppError::Format("unsupported KDBX version".to_string()))?;

    let header = read_header(&mut cursor, version)?;
    let header_end = usize::try_from(cursor.position())
        .map_err(|_| AppError::Format("header too large".to_string()))?;
    let (header_data, body) = data
        .split_at_checked(header_end)
        .ok_or_else(|| AppError::Format("truncated header".to_string()))?;

    // Check the header hash before running the KDF, so a corrupted header
    // (for example a garbled rounds count) fails at once instead of running
    // the KDF with junk parameters.
    if version.is_kdbx4() {
        let stored = body
            .get(..32)
            .ok_or_else(|| AppError::Format("truncated header hash".to_string()))?;
        if stored != crate::crypto::sha256(header_data) {
            return Err(AppError::Format("header hash mismatch".to_string()));
        }
    }

    if credentials.is_empty() {
        return Err(AppError::InvalidInput(
            "credentials required to decrypt database".to_string(),
        ));
    }

    let keys = credentials.derive_keys(version, &header.kdf, &header.master_seed)?;

    let (payload, header_hash) = if version.is_kdbx4() {
        let payload = read_kdbx4_payload(
            body,
            &header,
            header_data,
            &keys.final_key[..],
            &keys.transformed,
        )?;
        (payload, None)
    } else {
        let payload = read_kdbx3_payload(body, &header, &keys.final_key[..])?;
        (payload, Some(crate::crypto::sha256(header_data)))
    };
    // Only a result that decrypted the file is worth remembering.
    credentials.keep(&keys)?;

    let database = read_database(
        &payload.xml,
        &payload.attachments,
        &payload.protected_stream_key,
        payload.protected_stream,
        header_hash.as_ref().map(|hash| &hash[..]),
    )?;

    Ok(KdbxFile {
        version,
        public_custom_data: header.public_custom_data,
        cipher: header.cipher,
        compression: header.compression,
        kdf: header.kdf,
        protected_stream: payload.protected_stream,
        database,
    })
}

fn write_kdbx_bytes(file: &KdbxFile, credentials: &Credentials) -> AppResult<Vec<u8>> {
    if credentials.is_empty() {
        return Err(AppError::InvalidInput(
            "credentials required to encrypt database".to_string(),
        ));
    }

    let mut kdf = file.kdf.clone();
    randomize_kdf_seed(&mut kdf);

    let mut master_seed = vec![0u8; 32];
    OsRng.fill_bytes(&mut master_seed);

    let keys = credentials.derive_keys(file.version, &kdf, &master_seed)?;

    let data = if file.version.is_kdbx4() {
        write_kdbx4(
            file,
            &kdf,
            &master_seed,
            &keys.final_key[..],
            &keys.transformed,
        )?
    } else {
        write_kdbx3(file, &kdf, &master_seed, &keys.final_key[..])?
    };
    credentials.keep(&keys)?;
    Ok(data)
}

struct HeaderData {
    cipher: CipherId,
    compression: Compression,
    master_seed: Vec<u8>,
    encryption_iv: Vec<u8>,
    protected_stream: ProtectedStreamAlgo,
    protected_stream_key: Option<Vec<u8>>,
    kdf: KdfConfig,
    stream_start_bytes: Option<Vec<u8>>,
    public_custom_data: Option<Vec<u8>>,
}

fn read_header(cursor: &mut Cursor<&[u8]>, version: KdbxVersion) -> AppResult<HeaderData> {
    let mut cipher = None;
    let mut compression = None;
    let mut master_seed = None;
    let mut encryption_iv = None;
    let mut stream_start_bytes = None;
    let mut protected_stream = None;
    let mut protected_stream_key = None;
    let mut kdf = None;
    let mut transform_seed = None;
    let mut transform_rounds = None;
    let mut public_custom_data = None;

    loop {
        let field_id = {
            let mut buf = [0u8; 1];
            cursor.read_exact(&mut buf)?;
            buf[0]
        };

        let length = if version.is_kdbx4() {
            read_u32_le(cursor)? as usize
        } else {
            read_u16_le(cursor)? as usize
        };
        let data = if length == 0 {
            Vec::new()
        } else {
            read_vec(cursor, length)?
        };

        match field_id {
            x if x == HeaderFieldId::EndOfHeader as u8 => break,
            x if x == HeaderFieldId::CipherId as u8 => {
                let uuid = Uuid::from_slice(&data)
                    .map_err(|_| AppError::Format("invalid cipher UUID".to_string()))?;
                cipher = CipherId::from_uuid(uuid);
            }
            x if x == HeaderFieldId::CompressionFlags as u8 => {
                let value = le_u32(&data, "invalid compression flags")?;
                compression = Compression::from_u32(value);
            }
            x if x == HeaderFieldId::MasterSeed as u8 => master_seed = Some(data),
            x if x == HeaderFieldId::EncryptionIv as u8 => encryption_iv = Some(data),
            x if x == HeaderFieldId::ProtectedStreamKey as u8 => protected_stream_key = Some(data),
            x if x == HeaderFieldId::StreamStartBytes as u8 => stream_start_bytes = Some(data),
            x if x == HeaderFieldId::InnerRandomStreamId as u8 => {
                let id = le_u32(&data, "invalid inner stream id")?;
                protected_stream = ProtectedStreamAlgo::from_id(id);
            }
            x if x == HeaderFieldId::TransformSeed as u8 => {
                transform_seed = Some(data);
            }
            x if x == HeaderFieldId::TransformRounds as u8 => {
                let mut round_cursor = Cursor::new(&data);
                let rounds = read_u64_le(&mut round_cursor)?;
                transform_rounds = Some(rounds);
            }
            x if x == HeaderFieldId::KdfParameters as u8 => {
                let mut map_cursor = Cursor::new(&data);
                let map = read_variant_map(&mut map_cursor)?;
                kdf = Some(kdf_from_variant_map(&map)?);
            }
            x if x == HeaderFieldId::PublicCustomData as u8 && version.is_kdbx4() => {
                // Check it parses, but keep the original bytes.
                read_variant_map(&mut Cursor::new(&data))?;
                public_custom_data = Some(data);
            }
            _ => {}
        }
    }

    let cipher = cipher.ok_or_else(|| AppError::Format("missing cipher".to_string()))?;
    let compression =
        compression.ok_or_else(|| AppError::Format("missing compression".to_string()))?;
    let master_seed =
        master_seed.ok_or_else(|| AppError::Format("missing master seed".to_string()))?;
    let encryption_iv =
        encryption_iv.ok_or_else(|| AppError::Format("missing encryption IV".to_string()))?;

    let kdf = if version.is_kdbx4() {
        kdf.ok_or_else(|| AppError::Format("missing KDF parameters".to_string()))?
    } else {
        let seed =
            transform_seed.ok_or_else(|| AppError::Format("missing transform seed".to_string()))?;
        let rounds = transform_rounds
            .ok_or_else(|| AppError::Format("missing transform rounds".to_string()))?;
        KdfConfig::Aes {
            seed,
            rounds,
            legacy: true,
        }
    };

    let protected_stream = if version.is_kdbx4() {
        protected_stream.unwrap_or(ProtectedStreamAlgo::ChaCha20)
    } else {
        protected_stream.unwrap_or(ProtectedStreamAlgo::Salsa20)
    };

    Ok(HeaderData {
        cipher,
        compression,
        master_seed,
        encryption_iv,
        protected_stream,
        protected_stream_key,
        kdf,
        stream_start_bytes,
        public_custom_data,
    })
}

/// Read a 4-byte little-endian header value.
fn le_u32(data: &[u8], what: &str) -> AppResult<u32> {
    <[u8; 4]>::try_from(data)
        .map(u32::from_le_bytes)
        .map_err(|_| AppError::Format(what.to_string()))
}

fn build_final_key(
    master_seed: &[u8],
    challenge_response: Option<&[u8; 32]>,
    transformed: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(
        master_seed.len() + 32 + transformed.len(),
    ));
    buffer.extend_from_slice(master_seed);
    if let Some(response) = challenge_response {
        buffer.extend_from_slice(response);
    }
    buffer.extend_from_slice(transformed);
    Zeroizing::new(crate::crypto::sha256(&buffer))
}

/// The decrypted contents of a file. Every buffer is wiped when dropped.
struct PayloadData {
    xml: Zeroizing<Vec<u8>>,
    attachments: Vec<PoolBinary>,
    protected_stream: ProtectedStreamAlgo,
    protected_stream_key: Zeroizing<Vec<u8>>,
}

fn read_kdbx3_payload(
    data: &[u8],
    header: &HeaderData,
    final_key: &[u8],
) -> AppResult<PayloadData> {
    // With a wrong key the CBC padding is almost always invalid; when it is
    // not, the start bytes below catch it.
    let plain = decrypt(header.cipher, final_key, &header.encryption_iv, data)
        .map(Zeroizing::new)
        .map_err(|_| AppError::InvalidCredentials)?;

    let start_bytes = header
        .stream_start_bytes
        .as_ref()
        .ok_or_else(|| AppError::Format("missing stream start bytes".to_string()))?;
    let block_data = plain
        .strip_prefix(start_bytes.as_slice())
        .ok_or(AppError::InvalidCredentials)?;
    let decompressed = Zeroizing::new(decode_hashed_blocks(block_data)?);
    let xml = if header.compression == Compression::Gzip {
        decompress_gzip(&decompressed)?
    } else {
        decompressed
    };

    Ok(PayloadData {
        xml,
        attachments: Vec::new(),
        protected_stream: header.protected_stream,
        protected_stream_key: Zeroizing::new(
            header
                .protected_stream_key
                .clone()
                .ok_or_else(|| AppError::Format("missing protected stream key".to_string()))?,
        ),
    })
}

fn read_kdbx4_payload(
    data: &[u8],
    header: &HeaderData,
    header_data: &[u8],
    final_key: &[u8],
    transformed: &[u8],
) -> AppResult<PayloadData> {
    let mut cursor = Cursor::new(data);
    // The header hash was checked before the KDF ran.
    let _header_hash = read_vec(&mut cursor, 32)?;
    let header_hmac = read_vec(&mut cursor, 32)?;

    let hmac_key = Zeroizing::new(kdbx_hmac_key(&header.master_seed, transformed));
    let header_key = Zeroizing::new(hmac_block_key(u64::MAX, &hmac_key[..]));
    let expected = hmac_sha256(&header_key[..], header_data)?;
    if header_hmac != expected.to_vec() {
        // The header hash already matched, so the key is what is wrong.
        return Err(AppError::InvalidCredentials);
    }

    let blocks = usize::try_from(cursor.position())
        .ok()
        .and_then(|offset| data.get(offset..))
        .ok_or_else(|| AppError::Format("truncated HMAC blocks".to_string()))?;
    let ciphertext = decode_hmac_blocks(blocks, &hmac_key[..])?;
    let plain = Zeroizing::new(decrypt(
        header.cipher,
        final_key,
        &header.encryption_iv,
        &ciphertext,
    )?);

    let payload = if header.compression == Compression::Gzip {
        decompress_gzip(&plain)?
    } else {
        plain
    };

    let (inner_header, xml) = split_inner_header(&payload)?;

    Ok(PayloadData {
        xml,
        attachments: inner_header.binaries,
        protected_stream: inner_header.protected_stream,
        protected_stream_key: inner_header.protected_stream_key,
    })
}

struct InnerHeader {
    protected_stream: ProtectedStreamAlgo,
    protected_stream_key: Zeroizing<Vec<u8>>,
    binaries: Vec<PoolBinary>,
}

fn split_inner_header(payload: &[u8]) -> AppResult<(InnerHeader, Zeroizing<Vec<u8>>)> {
    let mut cursor = Cursor::new(payload);
    let mut protected_stream = None;
    let mut protected_stream_key = None;
    let mut binaries = Vec::new();

    loop {
        let mut id_buf = [0u8; 1];
        cursor.read_exact(&mut id_buf)?;
        let field_id = id_buf[0];
        let length = read_u32_le(&mut cursor)? as usize;
        // Inner header fields hold the stream key and attachment data.
        let data = Zeroizing::new(if length == 0 {
            Vec::new()
        } else {
            read_vec(&mut cursor, length)?
        });

        match field_id {
            x if x == InnerHeaderFieldId::End as u8 => break,
            x if x == InnerHeaderFieldId::InnerRandomStreamId as u8 => {
                let id = le_u32(&data, "invalid inner stream id")?;
                protected_stream = ProtectedStreamAlgo::from_id(id);
            }
            x if x == InnerHeaderFieldId::InnerRandomStreamKey as u8 => {
                protected_stream_key = Some(data);
            }
            x if x == InnerHeaderFieldId::Binary as u8 => {
                let (flags, content) = data
                    .split_first()
                    .ok_or_else(|| AppError::Format("invalid inner binary".to_string()))?;
                binaries.push(PoolBinary::new(content.to_vec(), flags & 0x01 != 0));
            }
            _ => {}
        }
    }

    let protected_stream = protected_stream.unwrap_or(ProtectedStreamAlgo::ChaCha20);
    let protected_stream_key = protected_stream_key
        .ok_or_else(|| AppError::Format("missing protected stream key".to_string()))?;

    let xml = Zeroizing::new(
        usize::try_from(cursor.position())
            .ok()
            .and_then(|offset| payload.get(offset..))
            .ok_or_else(|| AppError::Format("truncated inner header".to_string()))?
            .to_vec(),
    );
    Ok((
        InnerHeader {
            protected_stream,
            protected_stream_key,
            binaries,
        },
        xml,
    ))
}

fn decompress_gzip(data: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
    crate::xml::gunzip_limited(data).map(Zeroizing::new)
}

fn compress_gzip(data: &[u8]) -> AppResult<Zeroizing<Vec<u8>>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, data)?;
    Ok(Zeroizing::new(encoder.finish()?))
}

fn write_kdbx3(
    file: &KdbxFile,
    kdf: &KdfConfig,
    master_seed: &[u8],
    final_key: &[u8],
) -> AppResult<Vec<u8>> {
    let mut encryption_iv = vec![0u8; file.cipher.iv_len()];
    OsRng.fill_bytes(&mut encryption_iv);
    let mut protected_stream_key = Zeroizing::new(vec![0u8; 32]);
    OsRng.fill_bytes(&mut protected_stream_key);
    let mut stream_start_bytes = vec![0u8; 32];
    OsRng.fill_bytes(&mut stream_start_bytes);

    let mut header = Vec::new();
    write_u32_le(&mut header, KDBX_SIGNATURE_1)?;
    write_u32_le(&mut header, KDBX_SIGNATURE_2)?;
    write_u32_le(&mut header, FILE_VERSION_3_1)?;

    write_header_field_u16(
        &mut header,
        HeaderFieldId::CipherId,
        file.cipher.uuid().as_bytes(),
    )?;
    write_header_field_u16(
        &mut header,
        HeaderFieldId::CompressionFlags,
        &file.compression.as_u32().to_le_bytes(),
    )?;
    write_header_field_u16(&mut header, HeaderFieldId::MasterSeed, master_seed)?;

    let (seed, rounds) = match kdf {
        KdfConfig::Aes { seed, rounds, .. } => (seed.clone(), *rounds),
        _ => return Err(AppError::InvalidInput("KDBX3 requires AES-KDF".to_string())),
    };
    write_header_field_u16(&mut header, HeaderFieldId::TransformSeed, &seed)?;
    write_header_field_u16(
        &mut header,
        HeaderFieldId::TransformRounds,
        &rounds.to_le_bytes(),
    )?;

    write_header_field_u16(&mut header, HeaderFieldId::EncryptionIv, &encryption_iv)?;
    write_header_field_u16(
        &mut header,
        HeaderFieldId::ProtectedStreamKey,
        &protected_stream_key,
    )?;
    write_header_field_u16(
        &mut header,
        HeaderFieldId::StreamStartBytes,
        &stream_start_bytes,
    )?;
    let protected_id = ProtectedStreamAlgo::Salsa20.id().to_le_bytes();
    write_header_field_u16(
        &mut header,
        HeaderFieldId::InnerRandomStreamId,
        &protected_id,
    )?;
    write_header_field_u16(&mut header, HeaderFieldId::EndOfHeader, b"\r\n\r\n")?;

    let header_hash = crate::crypto::sha256(&header);
    let xml_output = write_database(
        &file.database,
        &protected_stream_key,
        ProtectedStreamAlgo::Salsa20,
        true,
        BinaryPool::Meta,
        Some(&header_hash),
    )?;
    let xml = Zeroizing::new(xml_output.xml);
    let payload = if file.compression == Compression::Gzip {
        compress_gzip(&xml)?
    } else {
        xml
    };

    let mut blocks = Zeroizing::new(Vec::new());
    blocks.extend_from_slice(&stream_start_bytes);
    blocks.extend_from_slice(&encode_hashed_blocks(&payload)?);

    let encrypted = encrypt(file.cipher, final_key, &encryption_iv, &blocks)?;

    let mut out = Vec::with_capacity(header.len() + encrypted.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

fn write_kdbx4(
    file: &KdbxFile,
    kdf: &KdfConfig,
    master_seed: &[u8],
    final_key: &[u8],
    transformed: &[u8],
) -> AppResult<Vec<u8>> {
    let mut encryption_iv = vec![0u8; file.cipher.iv_len()];
    OsRng.fill_bytes(&mut encryption_iv);
    let mut protected_stream_key = Zeroizing::new(vec![0u8; 64]);
    OsRng.fill_bytes(&mut protected_stream_key);

    let mut header = Vec::new();
    write_u32_le(&mut header, KDBX_SIGNATURE_1)?;
    write_u32_le(&mut header, KDBX_SIGNATURE_2)?;
    let version = if requires_kdbx41(&file.database) {
        KdbxVersion::V4_1
    } else {
        file.version
    };
    write_u32_le(&mut header, version.as_u32())?;

    write_header_field_u32(
        &mut header,
        HeaderFieldId::CipherId,
        file.cipher.uuid().as_bytes(),
    )?;
    write_header_field_u32(
        &mut header,
        HeaderFieldId::CompressionFlags,
        &file.compression.as_u32().to_le_bytes(),
    )?;
    write_header_field_u32(&mut header, HeaderFieldId::MasterSeed, master_seed)?;
    write_header_field_u32(&mut header, HeaderFieldId::EncryptionIv, &encryption_iv)?;

    let params = kdf_to_variant_map(kdf)?;
    let mut param_bytes = Vec::new();
    write_variant_map(&mut param_bytes, &params)?;
    write_header_field_u32(&mut header, HeaderFieldId::KdfParameters, &param_bytes)?;
    if let Some(data) = &file.public_custom_data {
        write_header_field_u32(&mut header, HeaderFieldId::PublicCustomData, data)?;
    }
    write_header_field_u32(&mut header, HeaderFieldId::EndOfHeader, b"\r\n\r\n")?;

    let header_hash = crate::crypto::sha256(&header).to_vec();
    let hmac_key = Zeroizing::new(kdbx_hmac_key(master_seed, transformed));
    let header_key = Zeroizing::new(hmac_block_key(u64::MAX, &hmac_key[..]));
    let header_hmac = hmac_sha256(&header_key[..], &header)?;

    let xml_output = write_database(
        &file.database,
        &protected_stream_key,
        file.protected_stream,
        true,
        BinaryPool::InnerHeader,
        None,
    )?;
    let attachments = xml_output.attachments;

    let mut inner_header = Zeroizing::new(Vec::new());
    write_inner_header_field(
        &mut inner_header,
        InnerHeaderFieldId::InnerRandomStreamId,
        &file.protected_stream.id().to_le_bytes(),
    )?;
    write_inner_header_field(
        &mut inner_header,
        InnerHeaderFieldId::InnerRandomStreamKey,
        &protected_stream_key,
    )?;
    for binary in &attachments {
        let mut data = zeroize::Zeroizing::new(Vec::with_capacity(binary.data.len() + 1));
        data.push(u8::from(binary.protected));
        data.extend_from_slice(&binary.data);
        write_inner_header_field(&mut inner_header, InnerHeaderFieldId::Binary, &data)?;
    }
    write_inner_header_field(&mut inner_header, InnerHeaderFieldId::End, &[])?;

    let xml = Zeroizing::new(xml_output.xml);
    let mut payload = Zeroizing::new(Vec::with_capacity(inner_header.len() + xml.len()));
    payload.extend_from_slice(&inner_header);
    payload.extend_from_slice(&xml);

    let payload = if file.compression == Compression::Gzip {
        compress_gzip(&payload)?
    } else {
        payload
    };

    let encrypted = encrypt(file.cipher, final_key, &encryption_iv, &payload)?;
    let hmac_blocks = encode_hmac_blocks(&encrypted, &hmac_key[..])?;

    let mut out = Vec::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(&header_hash);
    out.extend_from_slice(&header_hmac);
    out.extend_from_slice(&hmac_blocks);
    Ok(out)
}

fn write_header_field_u16(
    buffer: &mut Vec<u8>,
    field: HeaderFieldId,
    data: &[u8],
) -> AppResult<()> {
    buffer.push(field as u8);
    write_u16_le(buffer, data.len() as u16)?;
    buffer.extend_from_slice(data);
    Ok(())
}

fn write_header_field_u32(
    buffer: &mut Vec<u8>,
    field: HeaderFieldId,
    data: &[u8],
) -> AppResult<()> {
    buffer.push(field as u8);
    write_u32_le(buffer, data.len() as u32)?;
    buffer.extend_from_slice(data);
    Ok(())
}

fn write_inner_header_field(
    buffer: &mut Vec<u8>,
    field: InnerHeaderFieldId,
    data: &[u8],
) -> AppResult<()> {
    buffer.push(field as u8);
    write_u32_le(buffer, data.len() as u32)?;
    buffer.extend_from_slice(data);
    Ok(())
}

/// Give the KDF a fresh random 32-byte seed/salt.
///
/// Done on every save, like KeePassXC, so no two databases (or two saves of
/// one database) share a salt.
fn randomize_kdf_seed(kdf: &mut KdfConfig) {
    let seed = match kdf {
        KdfConfig::Aes { seed, .. } => seed,
        KdfConfig::Argon2 { salt, .. } => salt,
    };
    seed.resize(32, 0);
    OsRng.fill_bytes(seed);
}

fn kdf_to_variant_map(kdf: &KdfConfig) -> AppResult<BTreeMap<String, VariantValue>> {
    let mut map = BTreeMap::new();
    match kdf {
        KdfConfig::Aes { seed, rounds, .. } => {
            map.insert(
                "$UUID".to_string(),
                VariantValue::ByteArray(KdfType::AesKdbx3.uuid().as_bytes().to_vec()),
            );
            map.insert("R".to_string(), VariantValue::UInt64(*rounds));
            map.insert("S".to_string(), VariantValue::ByteArray(seed.clone()));
        }
        KdfConfig::Argon2 {
            kind,
            salt,
            iterations,
            memory_kib,
            parallelism,
            version,
        } => {
            map.insert(
                "$UUID".to_string(),
                VariantValue::ByteArray(kind.uuid().as_bytes().to_vec()),
            );
            map.insert("V".to_string(), VariantValue::UInt32(*version));
            map.insert("P".to_string(), VariantValue::UInt32(*parallelism));
            map.insert(
                "M".to_string(),
                VariantValue::UInt64((*memory_kib as u64) * 1024),
            );
            map.insert("I".to_string(), VariantValue::UInt64((*iterations) as u64));
            map.insert("S".to_string(), VariantValue::ByteArray(salt.clone()));
        }
    }
    Ok(map)
}

fn kdf_from_variant_map(map: &BTreeMap<String, VariantValue>) -> AppResult<KdfConfig> {
    let uuid = match map.get("$UUID") {
        Some(VariantValue::ByteArray(bytes)) => {
            Uuid::from_slice(bytes).map_err(|_| AppError::Format("invalid KDF UUID".to_string()))?
        }
        _ => return Err(AppError::Format("missing KDF UUID".to_string())),
    };

    match KdfType::from_uuid(uuid) {
        Some(KdfType::AesKdbx3) | Some(KdfType::AesKdbx4) => {
            let rounds = match map.get("R") {
                Some(VariantValue::UInt64(val)) => *val,
                _ => return Err(AppError::Format("missing AES rounds".to_string())),
            };
            let seed = match map.get("S") {
                Some(VariantValue::ByteArray(val)) => val.clone(),
                _ => return Err(AppError::Format("missing AES seed".to_string())),
            };
            Ok(KdfConfig::Aes {
                seed,
                rounds,
                legacy: false,
            })
        }
        Some(kind @ (KdfType::Argon2d | KdfType::Argon2id)) => {
            let version = match map.get("V") {
                Some(VariantValue::UInt32(val)) => *val,
                _ => return Err(AppError::Format("missing Argon2 version".to_string())),
            };
            let parallelism = match map.get("P") {
                Some(VariantValue::UInt32(val)) => *val,
                _ => return Err(AppError::Format("missing Argon2 parallelism".to_string())),
            };
            let memory_kib = match map.get("M") {
                // Rejected rather than truncated: a truncated value would be
                // written back on save and silently weaken the KDF.
                Some(VariantValue::UInt64(val)) => u32::try_from(*val / 1024)
                    .map_err(|_| AppError::Format("Argon2 memory out of range".to_string()))?,
                _ => return Err(AppError::Format("missing Argon2 memory".to_string())),
            };
            let iterations = match map.get("I") {
                Some(VariantValue::UInt64(val)) => u32::try_from(*val)
                    .map_err(|_| AppError::Format("Argon2 iterations out of range".to_string()))?,
                _ => return Err(AppError::Format("missing Argon2 iterations".to_string())),
            };

            let salt = match map.get("S") {
                Some(VariantValue::ByteArray(val)) => val.clone(),
                _ => return Err(AppError::Format("missing Argon2 salt".to_string())),
            };
            Ok(KdfConfig::Argon2 {
                kind,
                salt,
                iterations,
                memory_kib,
                parallelism,
                version,
            })
        }
        None => Err(AppError::Format("unsupported KDF UUID".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_file() -> (KdbxFile, Credentials) {
        let file = KdbxFile {
            version: KdbxVersion::V4_0,
            public_custom_data: None,
            cipher: CipherId::Aes256,
            compression: Compression::Gzip,
            kdf: KdfConfig::Argon2 {
                kind: KdfType::Argon2id,
                salt: vec![0u8; 32],
                iterations: 1,
                memory_kib: 64,
                parallelism: 1,
                version: 0x13,
            },
            protected_stream: ProtectedStreamAlgo::ChaCha20,
            database: Database::new("Test".to_string()),
        };
        let credentials = Credentials {
            password: Some(SecretString::new("pw".to_string())),
            key_file: None,
            yubikey: None,
            agent: None,
        };
        (file, credentials)
    }

    #[test]
    fn every_save_uses_a_fresh_kdf_salt() {
        let (file, credentials) = test_file();
        let first = write_kdbx_bytes(&file, &credentials).expect("write");
        let second = write_kdbx_bytes(&file, &credentials).expect("write");
        let first = read_kdbx_bytes(&first, &credentials).expect("read");
        let second = read_kdbx_bytes(&second, &credentials).expect("read");
        assert_ne!(first.kdf.seed(), &[0u8; 32]);
        assert_ne!(first.kdf.seed(), second.kdf.seed());
    }

    #[test]
    fn atomic_write_replaces_file() {
        let (file, credentials) = test_file();
        let dir = std::env::temp_dir().join(format!("keepassxcr-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("db.kdbx");
        fs::write(&path, b"old").expect("seed file");
        write_kdbx(&path, &file, &credentials).expect("write");
        read_kdbx(&path, &credentials).expect("read back");
        let leftovers = fs::read_dir(&dir).expect("list").count();
        assert_eq!(leftovers, 1, "temporary file left behind");
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn attachment_protection_flag_survives_a_save() {
        let (mut file, credentials) = test_file();
        let mut entry = crate::model::Entry::new("E".to_string());
        entry
            .attachments_mut()
            .push(crate::model::Attachment::with_protection(
                "plain.txt".to_string(),
                b"plain".to_vec(),
                false,
            ));
        entry.attachments_mut().push(crate::model::Attachment::new(
            "secret.txt".to_string(),
            b"s".to_vec(),
        ));
        file.database.root_mut().entries_mut().push(entry);
        let bytes = write_kdbx_bytes(&file, &credentials).expect("write");
        let read = read_kdbx_bytes(&bytes, &credentials).expect("read");
        let flags: Vec<bool> = read.database.root().entries()[0]
            .attachments()
            .iter()
            .map(crate::model::Attachment::protected)
            .collect();
        assert_eq!(flags, vec![false, true]);
    }

    fn kdbx3_file() -> KdbxFile {
        let (mut file, _) = test_file();
        file.version = KdbxVersion::V3_1;
        file.kdf = KdfConfig::Aes {
            seed: vec![0u8; 32],
            rounds: 1,
            legacy: true,
        };
        file.protected_stream = ProtectedStreamAlgo::Salsa20;
        file
    }

    #[test]
    fn version_is_kept_unless_a_41_feature_needs_it() {
        let (mut file, credentials) = test_file();
        let saved = write_kdbx_bytes(&file, &credentials).expect("write");
        let read = read_kdbx_bytes(&saved, &credentials).expect("read");
        assert_eq!(read.version, KdbxVersion::V4_0);

        file.database.root_mut().set_tags("work".to_string());
        let saved = write_kdbx_bytes(&file, &credentials).expect("write");
        let read = read_kdbx_bytes(&saved, &credentials).expect("read");
        assert_eq!(read.version, KdbxVersion::V4_1);
    }

    #[test]
    fn public_custom_data_survives_a_save() {
        let (mut file, credentials) = test_file();
        let mut map = BTreeMap::new();
        map.insert(
            "plugin".to_string(),
            VariantValue::String("value".to_string()),
        );
        map.insert("count".to_string(), VariantValue::UInt64(7));
        let mut data = Vec::new();
        write_variant_map(&mut data, &map).expect("map");
        file.public_custom_data = Some(data.clone());

        let saved = write_kdbx_bytes(&file, &credentials).expect("write");
        let read = read_kdbx_bytes(&saved, &credentials).expect("read");
        assert_eq!(read.public_custom_data, Some(data));
    }

    #[test]
    fn kdbx3_header_changes_are_detected() {
        let file = kdbx3_file();
        let (_, credentials) = test_file();
        let saved = write_kdbx_bytes(&file, &credentials).expect("write");
        read_kdbx_bytes(&saved, &credentials).expect("untouched file opens");

        // A comment field changes nothing that decryption uses, so only the
        // stored header hash can catch it.
        let mut tampered = saved[..12].to_vec();
        tampered.extend_from_slice(&[HeaderFieldId::Comment as u8, 3, 0]);
        tampered.extend_from_slice(b"hi!");
        tampered.extend_from_slice(&saved[12..]);
        let err = read_kdbx_bytes(&tampered, &credentials).expect_err("tampered header opened");
        assert!(err.to_string().contains("header hash mismatch"), "{err}");
    }

    #[test]
    fn wrong_credentials_are_reported_as_such() {
        let (file4, credentials) = test_file();
        let wrong = Credentials {
            password: Some(SecretString::new("wrong".to_string())),
            key_file: None,
            yubikey: None,
            agent: None,
        };
        for file in [file4, kdbx3_file()] {
            let saved = write_kdbx_bytes(&file, &credentials).expect("write");
            let err = read_kdbx_bytes(&saved, &wrong).expect_err("opened with wrong password");
            assert!(matches!(err, AppError::InvalidCredentials), "{err}");
        }
    }

    #[test]
    fn credentials_debug_hides_the_password() {
        let (_, credentials) = test_file();
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("pw\""), "{debug}");
    }

    #[test]
    fn kdf_variant_roundtrip() {
        let kdf = KdfConfig::Argon2 {
            kind: KdfType::Argon2id,
            salt: vec![1u8; 32],
            iterations: 2,
            memory_kib: 32,
            parallelism: 1,
            version: 0x13,
        };
        let map = kdf_to_variant_map(&kdf).expect("map");
        let restored = kdf_from_variant_map(&map).expect("restore");
        match restored {
            KdfConfig::Argon2 { kind, .. } => assert_eq!(kind, KdfType::Argon2id),
            _ => panic!("expected argon2"),
        }
    }
}
