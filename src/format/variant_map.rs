use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::error::{AppError, AppResult};
use crate::format::constants::{VARIANT_MAP_CRITICAL_MASK, VARIANT_MAP_VERSION, VariantFieldType};
use crate::util::{read_u16_le, read_u32_le, read_vec, write_u16_le, write_u32_le};

/// Variant map value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantValue {
    /// Boolean value.
    Bool(bool),
    /// Signed 32-bit integer.
    Int32(i32),
    /// Unsigned 32-bit integer.
    UInt32(u32),
    /// Signed 64-bit integer.
    Int64(i64),
    /// Unsigned 64-bit integer.
    UInt64(u64),
    /// UTF-8 string.
    String(String),
    /// Raw bytes.
    ByteArray(Vec<u8>),
}

/// Read a variant map from the reader.
pub fn read_variant_map<R: Read>(reader: &mut R) -> AppResult<BTreeMap<String, VariantValue>> {
    let version = read_u16_le(reader)? & VARIANT_MAP_CRITICAL_MASK;
    if version > (VARIANT_MAP_VERSION & VARIANT_MAP_CRITICAL_MASK) {
        return Err(AppError::Format(
            "unsupported variant map version".to_string(),
        ));
    }

    let mut map = BTreeMap::new();
    loop {
        let field_type = {
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf)?;
            buf[0]
        };
        if field_type == VariantFieldType::End as u8 {
            break;
        }

        let name_len = read_u32_le(reader)? as usize;
        let name_bytes = if name_len == 0 {
            Vec::new()
        } else {
            read_vec(reader, name_len)?
        };
        let name = String::from_utf8(name_bytes)
            .map_err(|_| AppError::Format("invalid variant map name".to_string()))?;

        let value_len = read_u32_le(reader)? as usize;
        let value_bytes = if value_len == 0 {
            Vec::new()
        } else {
            read_vec(reader, value_len)?
        };

        let value = match field_type {
            x if x == VariantFieldType::Bool as u8 => {
                if value_bytes.len() != 1 {
                    return Err(AppError::Format("invalid bool value length".to_string()));
                }
                VariantValue::Bool(value_bytes[0] != 0)
            }
            x if x == VariantFieldType::Int32 as u8 => {
                if value_bytes.len() != 4 {
                    return Err(AppError::Format("invalid int32 value length".to_string()));
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&value_bytes);
                VariantValue::Int32(i32::from_le_bytes(buf))
            }
            x if x == VariantFieldType::UInt32 as u8 => {
                if value_bytes.len() != 4 {
                    return Err(AppError::Format("invalid uint32 value length".to_string()));
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&value_bytes);
                VariantValue::UInt32(u32::from_le_bytes(buf))
            }
            x if x == VariantFieldType::Int64 as u8 => {
                if value_bytes.len() != 8 {
                    return Err(AppError::Format("invalid int64 value length".to_string()));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&value_bytes);
                VariantValue::Int64(i64::from_le_bytes(buf))
            }
            x if x == VariantFieldType::UInt64 as u8 => {
                if value_bytes.len() != 8 {
                    return Err(AppError::Format("invalid uint64 value length".to_string()));
                }
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&value_bytes);
                VariantValue::UInt64(u64::from_le_bytes(buf))
            }
            x if x == VariantFieldType::String as u8 => {
                let value = String::from_utf8(value_bytes)
                    .map_err(|_| AppError::Format("invalid string value".to_string()))?;
                VariantValue::String(value)
            }
            x if x == VariantFieldType::ByteArray as u8 => VariantValue::ByteArray(value_bytes),
            _ => return Err(AppError::Format("unsupported variant map type".to_string())),
        };

        map.insert(name, value);
    }

    Ok(map)
}

/// Write a variant map to the writer.
pub fn write_variant_map<W: Write>(
    writer: &mut W,
    map: &BTreeMap<String, VariantValue>,
) -> AppResult<()> {
    write_u16_le(writer, VARIANT_MAP_VERSION)?;
    for (name, value) in map {
        let (field_type, bytes): (VariantFieldType, Vec<u8>) = match value {
            VariantValue::Bool(val) => (VariantFieldType::Bool, vec![*val as u8]),
            VariantValue::Int32(val) => (VariantFieldType::Int32, val.to_le_bytes().to_vec()),
            VariantValue::UInt32(val) => (VariantFieldType::UInt32, val.to_le_bytes().to_vec()),
            VariantValue::Int64(val) => (VariantFieldType::Int64, val.to_le_bytes().to_vec()),
            VariantValue::UInt64(val) => (VariantFieldType::UInt64, val.to_le_bytes().to_vec()),
            VariantValue::String(val) => (VariantFieldType::String, val.as_bytes().to_vec()),
            VariantValue::ByteArray(val) => (VariantFieldType::ByteArray, val.clone()),
        };

        writer.write_all(&[field_type as u8])?;
        write_u32_le(writer, name.len() as u32)?;
        if !name.is_empty() {
            writer.write_all(name.as_bytes())?;
        }
        write_u32_le(writer, bytes.len() as u32)?;
        if !bytes.is_empty() {
            writer.write_all(&bytes)?;
        }
    }

    writer.write_all(&[VariantFieldType::End as u8])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_map_roundtrip() {
        let mut map = BTreeMap::new();
        map.insert("I".to_string(), VariantValue::UInt64(5));
        map.insert("S".to_string(), VariantValue::ByteArray(vec![1, 2, 3]));

        let mut buf = Vec::new();
        write_variant_map(&mut buf, &map).expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        let read = read_variant_map(&mut cursor).expect("read");
        assert_eq!(read, map);
    }
}
