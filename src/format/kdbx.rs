use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::SecretString;
use uuid::Uuid;

use crate::crypto::{
    CipherId, CompositeKey, KdfConfig, KdfType, KeyFile, ProtectedStreamAlgo, decrypt, encrypt,
    hmac_sha256, kdbx_hmac_key,
};
use crate::error::{AppError, AppResult};
use crate::format::block_stream::{
    decode_hashed_blocks, decode_hmac_blocks, encode_hashed_blocks, encode_hmac_blocks,
    hmac_block_key,
};
use crate::format::constants::{
    FILE_VERSION_3_1, FILE_VERSION_4_1, HeaderFieldId, InnerHeaderFieldId, KDBX_SIGNATURE_1,
    KDBX_SIGNATURE_2,
};
use crate::format::types::{Compression, KdbxVersion};
use crate::format::variant_map::{VariantValue, read_variant_map, write_variant_map};
use crate::model::Database;
use crate::util::{read_u16_le, read_u32_le, read_u64_le, read_vec, write_u16_le, write_u32_le};
use crate::xml::{read_database, write_database};

/// Credentials for database operations.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// Optional password.
    pub password: Option<SecretString>,
    /// Optional key file.
    pub key_file: Option<KeyFile>,
    /// Optional challenge-response bytes.
    pub challenge_response: Option<Vec<u8>>,
}

impl Credentials {
    /// Build a composite key from credentials.
    pub fn composite_key(&self) -> AppResult<CompositeKey> {
        let mut composite = CompositeKey::new();
        if let Some(password) = &self.password {
            composite.add_password(password);
        }
        if let Some(key_file) = &self.key_file {
            composite.add_keyfile(key_file);
        }
        if let Some(response) = &self.challenge_response {
            composite.add_component(response.clone());
        }
        Ok(composite)
    }

    /// True if no credential components were provided.
    pub fn is_empty(&self) -> bool {
        self.password.is_none() && self.key_file.is_none() && self.challenge_response.is_none()
    }
}

/// Parsed KDBX file with settings and data.
#[derive(Debug, Clone)]
pub struct KdbxFile {
    /// KDBX version.
    pub version: KdbxVersion,
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
pub fn write_kdbx(path: &Path, file: &KdbxFile, credentials: &Credentials) -> AppResult<()> {
    let data = write_kdbx_bytes(file, credentials)?;
    fs::write(path, data)?;
    Ok(())
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
    let header_end = cursor.position() as usize;
    let header_data = &data[..header_end];

    if credentials.is_empty() {
        return Err(AppError::InvalidInput(
            "credentials required to decrypt database".to_string(),
        ));
    }

    let composite = credentials.composite_key()?;
    if composite.is_empty() {
        return Err(AppError::InvalidInput("empty composite key".to_string()));
    }

    let raw_key = composite.raw_key();
    let transformed = header.kdf.transform(&raw_key)?;
    let final_key = build_final_key(&header.master_seed, &transformed, credentials)?;

    let payload = if version.is_kdbx4() {
        read_kdbx4_payload(
            &data[header_end..],
            &header,
            header_data,
            &final_key,
            &transformed,
        )?
    } else {
        read_kdbx3_payload(&data[header_end..], &header, &final_key)?
    };

    let database = read_database(
        &payload.xml,
        &payload.attachments,
        &payload.protected_stream_key,
        payload.protected_stream,
    )?;

    Ok(KdbxFile {
        version,
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

    let composite = credentials.composite_key()?;
    if composite.is_empty() {
        return Err(AppError::InvalidInput("empty composite key".to_string()));
    }

    let mut kdf = file.kdf.clone();
    ensure_kdf_seed(&mut kdf)?;

    let raw_key = composite.raw_key();
    let transformed = kdf.transform(&raw_key)?;
    let mut master_seed = vec![0u8; 32];
    OsRng.fill_bytes(&mut master_seed);

    let final_key = build_final_key(&master_seed, &transformed, credentials)?;

    if file.version.is_kdbx4() {
        write_kdbx4(file, &kdf, &master_seed, &final_key, &transformed)
    } else {
        write_kdbx3(file, &kdf, &master_seed, &final_key)
    }
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
                if data.len() != 4 {
                    return Err(AppError::Format("invalid compression flags".to_string()));
                }
                let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                compression = Compression::from_u32(value);
            }
            x if x == HeaderFieldId::MasterSeed as u8 => master_seed = Some(data),
            x if x == HeaderFieldId::EncryptionIv as u8 => encryption_iv = Some(data),
            x if x == HeaderFieldId::ProtectedStreamKey as u8 => protected_stream_key = Some(data),
            x if x == HeaderFieldId::StreamStartBytes as u8 => stream_start_bytes = Some(data),
            x if x == HeaderFieldId::InnerRandomStreamId as u8 => {
                if data.len() != 4 {
                    return Err(AppError::Format("invalid inner stream id".to_string()));
                }
                let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
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
    })
}

fn build_final_key(
    master_seed: &[u8],
    transformed: &[u8],
    _credentials: &Credentials,
) -> AppResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(master_seed.len() + transformed.len());
    buffer.extend_from_slice(master_seed);
    buffer.extend_from_slice(transformed);
    Ok(crate::crypto::sha256(&buffer).to_vec())
}

struct PayloadData {
    xml: Vec<u8>,
    attachments: Vec<Vec<u8>>,
    protected_stream: ProtectedStreamAlgo,
    protected_stream_key: Vec<u8>,
}

fn read_kdbx3_payload(
    data: &[u8],
    header: &HeaderData,
    final_key: &[u8],
) -> AppResult<PayloadData> {
    let cipher_text = data.to_vec();
    let plain = decrypt(
        header.cipher,
        final_key,
        &header.encryption_iv,
        &cipher_text,
    )?;

    let start_bytes = header
        .stream_start_bytes
        .as_ref()
        .ok_or_else(|| AppError::Format("missing stream start bytes".to_string()))?;
    if plain.len() < start_bytes.len() || &plain[..start_bytes.len()] != start_bytes {
        return Err(AppError::Format("invalid credentials".to_string()));
    }

    let block_data = &plain[start_bytes.len()..];
    let decompressed = decode_hashed_blocks(block_data)?;
    let xml = if header.compression == Compression::Gzip {
        decompress_gzip(&decompressed)?
    } else {
        decompressed
    };

    Ok(PayloadData {
        xml,
        attachments: Vec::new(),
        protected_stream: header.protected_stream,
        protected_stream_key: header
            .protected_stream_key
            .clone()
            .ok_or_else(|| AppError::Format("missing protected stream key".to_string()))?,
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
    let header_hash = read_vec(&mut cursor, 32)?;
    let header_hmac = read_vec(&mut cursor, 32)?;

    if header_hash != crate::crypto::sha256(header_data).to_vec() {
        return Err(AppError::Format("header hash mismatch".to_string()));
    }

    let hmac_key = kdbx_hmac_key(&header.master_seed, transformed);
    let header_key = hmac_block_key(u64::MAX, &hmac_key);
    let expected = hmac_sha256(&header_key, header_data)?;
    if header_hmac != expected.to_vec() {
        return Err(AppError::Format("header HMAC mismatch".to_string()));
    }

    let ciphertext = decode_hmac_blocks(&data[(cursor.position() as usize)..], &hmac_key)?;
    let plain = decrypt(header.cipher, final_key, &header.encryption_iv, &ciphertext)?;

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
    protected_stream_key: Vec<u8>,
    binaries: Vec<Vec<u8>>,
}

fn split_inner_header(payload: &[u8]) -> AppResult<(InnerHeader, Vec<u8>)> {
    let mut cursor = Cursor::new(payload);
    let mut protected_stream = None;
    let mut protected_stream_key = None;
    let mut binaries = Vec::new();

    loop {
        let mut id_buf = [0u8; 1];
        cursor.read_exact(&mut id_buf)?;
        let field_id = id_buf[0];
        let length = read_u32_le(&mut cursor)? as usize;
        let data = if length == 0 {
            Vec::new()
        } else {
            read_vec(&mut cursor, length)?
        };

        match field_id {
            x if x == InnerHeaderFieldId::End as u8 => break,
            x if x == InnerHeaderFieldId::InnerRandomStreamId as u8 => {
                if data.len() != 4 {
                    return Err(AppError::Format("invalid inner stream id".to_string()));
                }
                let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                protected_stream = ProtectedStreamAlgo::from_id(id);
            }
            x if x == InnerHeaderFieldId::InnerRandomStreamKey as u8 => {
                protected_stream_key = Some(data);
            }
            x if x == InnerHeaderFieldId::Binary as u8 => {
                if data.is_empty() {
                    return Err(AppError::Format("invalid inner binary".to_string()));
                }
                binaries.push(data[1..].to_vec());
            }
            _ => {}
        }
    }

    let protected_stream = protected_stream.unwrap_or(ProtectedStreamAlgo::ChaCha20);
    let protected_stream_key = protected_stream_key
        .ok_or_else(|| AppError::Format("missing protected stream key".to_string()))?;

    let offset = cursor.position() as usize;
    let xml = payload[offset..].to_vec();
    Ok((
        InnerHeader {
            protected_stream,
            protected_stream_key,
            binaries,
        },
        xml,
    ))
}

fn decompress_gzip(data: &[u8]) -> AppResult<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut out)?;
    Ok(out)
}

fn compress_gzip(data: &[u8]) -> AppResult<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, data)?;
    Ok(encoder.finish()?)
}

fn write_kdbx3(
    file: &KdbxFile,
    kdf: &KdfConfig,
    master_seed: &[u8],
    final_key: &[u8],
) -> AppResult<Vec<u8>> {
    let mut encryption_iv = vec![0u8; file.cipher.iv_len()];
    OsRng.fill_bytes(&mut encryption_iv);
    let mut protected_stream_key = vec![0u8; 32];
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

    let xml_output = write_database(
        &file.database,
        &protected_stream_key,
        ProtectedStreamAlgo::Salsa20,
        true,
    )?;
    let payload = if file.compression == Compression::Gzip {
        compress_gzip(&xml_output.xml)?
    } else {
        xml_output.xml
    };

    let mut blocks = Vec::new();
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
    let mut protected_stream_key = vec![0u8; 64];
    OsRng.fill_bytes(&mut protected_stream_key);

    let mut header = Vec::new();
    write_u32_le(&mut header, KDBX_SIGNATURE_1)?;
    write_u32_le(&mut header, KDBX_SIGNATURE_2)?;
    write_u32_le(&mut header, FILE_VERSION_4_1)?;

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
    write_header_field_u32(&mut header, HeaderFieldId::EndOfHeader, b"\r\n\r\n")?;

    let header_hash = crate::crypto::sha256(&header).to_vec();
    let hmac_key = kdbx_hmac_key(master_seed, transformed);
    let header_key = hmac_block_key(u64::MAX, &hmac_key);
    let header_hmac = hmac_sha256(&header_key, &header)?;

    let xml_output = write_database(
        &file.database,
        &protected_stream_key,
        file.protected_stream,
        true,
    )?;
    let attachments = xml_output.attachments;

    let mut inner_header = Vec::new();
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
        let mut data = Vec::with_capacity(binary.len() + 1);
        data.push(0x01);
        data.extend_from_slice(binary);
        write_inner_header_field(&mut inner_header, InnerHeaderFieldId::Binary, &data)?;
    }
    write_inner_header_field(&mut inner_header, InnerHeaderFieldId::End, &[])?;

    let mut payload = Vec::new();
    payload.extend_from_slice(&inner_header);
    payload.extend_from_slice(&xml_output.xml);

    let payload = if file.compression == Compression::Gzip {
        compress_gzip(&payload)?
    } else {
        payload
    };

    let encrypted = encrypt(file.cipher, final_key, &encryption_iv, &payload)?;
    let hmac_blocks = encode_hmac_blocks(&encrypted, &hmac_key)?;

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

fn ensure_kdf_seed(kdf: &mut KdfConfig) -> AppResult<()> {
    match kdf {
        KdfConfig::Aes { seed, .. } => {
            if seed.is_empty() {
                seed.resize(32, 0);
                OsRng.fill_bytes(seed);
            }
        }
        KdfConfig::Argon2 { salt, .. } => {
            if salt.is_empty() {
                salt.resize(32, 0);
                OsRng.fill_bytes(salt);
            }
        }
    }
    Ok(())
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
        Some(KdfType::Argon2d) | Some(KdfType::Argon2id) => {
            let kind = KdfType::from_uuid(uuid).expect("validated");
            let version = match map.get("V") {
                Some(VariantValue::UInt32(val)) => *val,
                _ => return Err(AppError::Format("missing Argon2 version".to_string())),
            };
            let parallelism = match map.get("P") {
                Some(VariantValue::UInt32(val)) => *val,
                _ => return Err(AppError::Format("missing Argon2 parallelism".to_string())),
            };
            let memory_kib = match map.get("M") {
                Some(VariantValue::UInt64(val)) => (*val / 1024) as u32,
                _ => return Err(AppError::Format("missing Argon2 memory".to_string())),
            };
            let iterations = match map.get("I") {
                Some(VariantValue::UInt64(val)) => *val as u32,
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
