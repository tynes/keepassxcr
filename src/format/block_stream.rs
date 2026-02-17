use crate::crypto::{hmac_sha256, sha256, sha512};
use crate::error::{AppError, AppResult};
use crate::util::{read_array, read_u32_le, read_vec, write_u32_le};

const DEFAULT_BLOCK_SIZE: usize = 1024 * 1024;

/// Encode data into KDBX3 hashed blocks.
pub fn encode_hashed_blocks(data: &[u8]) -> AppResult<Vec<u8>> {
    let mut out = Vec::new();
    let mut index = 0u32;
    for chunk in data.chunks(DEFAULT_BLOCK_SIZE) {
        write_u32_le(&mut out, index)?;
        let hash = sha256(chunk);
        out.extend_from_slice(&hash);
        write_u32_le(&mut out, chunk.len() as u32)?;
        out.extend_from_slice(chunk);
        index += 1;
    }

    write_u32_le(&mut out, index)?;
    out.extend_from_slice(&[0u8; 32]);
    write_u32_le(&mut out, 0)?;

    Ok(out)
}

/// Decode KDBX3 hashed blocks.
pub fn decode_hashed_blocks(data: &[u8]) -> AppResult<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(data);
    let mut expected_index = 0u32;
    let mut out = Vec::new();

    loop {
        let index = read_u32_le(&mut cursor)?;
        if index != expected_index {
            return Err(AppError::Format("invalid block index".to_string()));
        }
        let hash = read_array::<32, _>(&mut cursor)?;
        let size = read_u32_le(&mut cursor)? as usize;
        if size == 0 {
            if hash.iter().any(|&b| b != 0) {
                return Err(AppError::Format("invalid final block hash".to_string()));
            }
            break;
        }
        let block = read_vec(&mut cursor, size)?;
        if sha256(&block) != hash {
            return Err(AppError::Format("block hash mismatch".to_string()));
        }
        out.extend_from_slice(&block);
        expected_index += 1;
    }

    Ok(out)
}

/// Encode data into KDBX4 HMAC blocks.
pub fn encode_hmac_blocks(data: &[u8], hmac_key: &[u8]) -> AppResult<Vec<u8>> {
    if hmac_key.len() != 64 {
        return Err(AppError::Crypto("HMAC key must be 64 bytes".to_string()));
    }

    let mut out = Vec::new();
    let mut index = 0u64;
    for chunk in data.chunks(DEFAULT_BLOCK_SIZE) {
        let block_key = hmac_block_key(index, hmac_key);
        let mut header = Vec::with_capacity(12 + chunk.len());
        header.extend_from_slice(&index.to_le_bytes());
        header.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        header.extend_from_slice(chunk);
        let hmac = hmac_sha256(&block_key, &header)?;
        out.extend_from_slice(&hmac);
        write_u32_le(&mut out, chunk.len() as u32)?;
        out.extend_from_slice(chunk);
        index += 1;
    }

    let block_key = hmac_block_key(index, hmac_key);
    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(&index.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    let hmac = hmac_sha256(&block_key, &header)?;
    out.extend_from_slice(&hmac);
    write_u32_le(&mut out, 0)?;

    Ok(out)
}

/// Decode KDBX4 HMAC blocks.
pub fn decode_hmac_blocks(data: &[u8], hmac_key: &[u8]) -> AppResult<Vec<u8>> {
    if hmac_key.len() != 64 {
        return Err(AppError::Crypto("HMAC key must be 64 bytes".to_string()));
    }

    let mut cursor = std::io::Cursor::new(data);
    let mut index = 0u64;
    let mut out = Vec::new();

    loop {
        let hmac = read_array::<32, _>(&mut cursor)?;
        let size = read_u32_le(&mut cursor)? as usize;
        let block = read_vec(&mut cursor, size)?;

        let block_key = hmac_block_key(index, hmac_key);
        let mut header = Vec::with_capacity(12 + block.len());
        header.extend_from_slice(&index.to_le_bytes());
        header.extend_from_slice(&(size as u32).to_le_bytes());
        header.extend_from_slice(&block);
        let expected = hmac_sha256(&block_key, &header)?;
        if expected != hmac {
            return Err(AppError::Format("HMAC block mismatch".to_string()));
        }

        if size == 0 {
            break;
        }
        out.extend_from_slice(&block);
        index += 1;
    }

    Ok(out)
}

/// Derive the per-block HMAC key.
pub fn hmac_block_key(index: u64, hmac_key: &[u8]) -> [u8; 64] {
    let mut data = Vec::with_capacity(8 + hmac_key.len());
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(hmac_key);
    sha512(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_blocks_roundtrip() {
        let data = b"hello".repeat(1000);
        let encoded = encode_hashed_blocks(data.as_slice()).expect("encode");
        let decoded = decode_hashed_blocks(&encoded).expect("decode");
        assert_eq!(decoded, data.as_slice());
    }

    #[test]
    fn hmac_blocks_roundtrip() {
        let data = b"hello".repeat(1000);
        let key = [7u8; 64];
        let encoded = encode_hmac_blocks(data.as_slice(), &key).expect("encode");
        let decoded = decode_hmac_blocks(&encoded, &key).expect("decode");
        assert_eq!(decoded, data.as_slice());
    }
}
