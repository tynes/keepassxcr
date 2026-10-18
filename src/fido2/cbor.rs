//! The small part of CBOR (RFC 8949) that CTAP2 uses: integers, byte and
//! text strings, arrays, maps and booleans.
//!
//! Maps are written in CTAP2's canonical order (shorter keys first, then
//! bytewise), which authenticators insist on.

use crate::error::{AppError, AppResult};

/// Nesting limit when decoding, so a hostile device cannot exhaust the stack.
const MAX_DEPTH: usize = 16;

/// A CBOR value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    /// A map with integer keys.
    pub fn int_map(entries: Vec<(i64, Value)>) -> Self {
        Self::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Self::Int(k), v))
                .collect(),
        )
    }

    /// A map with text keys.
    pub fn text_map(entries: Vec<(&str, Value)>) -> Self {
        Self::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Self::Text(k.to_string()), v))
                .collect(),
        )
    }

    pub fn text(value: &str) -> Self {
        Self::Text(value.to_string())
    }

    /// The value under `key` in a map.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Self::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_int(&self, key: i64) -> Option<&Value> {
        self.get(&Self::Int(key))
    }

    pub fn get_text(&self, key: &str) -> Option<&Value> {
        self.get(&Self::text(key))
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Encode in CTAP2 canonical form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int(value) if *value >= 0 => head(out, 0, *value as u64),
            Self::Int(value) => head(out, 1, !(*value) as u64),
            Self::Bytes(bytes) => {
                head(out, 2, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Self::Text(text) => {
                head(out, 3, text.len() as u64);
                out.extend_from_slice(text.as_bytes());
            }
            Self::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.encode_into(out);
                }
            }
            Self::Map(entries) => {
                let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                    .iter()
                    .map(|(k, v)| (k.encode(), v.encode()))
                    .collect();
                encoded.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
                head(out, 5, encoded.len() as u64);
                for (k, v) in encoded {
                    out.extend_from_slice(&k);
                    out.extend_from_slice(&v);
                }
            }
            Self::Bool(false) => out.push(0xf4),
            Self::Bool(true) => out.push(0xf5),
            Self::Null => out.push(0xf6),
        }
    }

    /// Decode one value that fills `data` exactly.
    ///
    /// # Errors
    ///
    /// Fails on malformed or unsupported CBOR, or trailing bytes.
    pub fn decode(data: &[u8]) -> AppResult<Self> {
        let mut reader = Reader { data, pos: 0 };
        let value = reader.value(0)?;
        if reader.pos != data.len() {
            return Err(cbor_error("trailing bytes"));
        }
        Ok(value)
    }

    /// Decode one value from the start of `data`, returning it and its length.
    ///
    /// # Errors
    ///
    /// Fails on malformed or unsupported CBOR.
    pub fn decode_prefix(data: &[u8]) -> AppResult<(Self, usize)> {
        let mut reader = Reader { data, pos: 0 };
        let value = reader.value(0)?;
        Ok((value, reader.pos))
    }
}

fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn cbor_error(what: &str) -> AppError {
    AppError::Fido2(format!("malformed CBOR from the security key: {what}"))
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> AppResult<&[u8]> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| cbor_error("truncated"))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn argument(&mut self, info: u8) -> AppResult<u64> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().unwrap_or_default(),
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().unwrap_or_default(),
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap_or_default()),
            _ => return Err(cbor_error("indefinite lengths are not supported")),
        })
    }

    fn length(&mut self, info: u8) -> AppResult<usize> {
        let len = self.argument(info)?;
        // Every element takes at least one byte, so this bounds allocations.
        usize::try_from(len)
            .ok()
            .filter(|len| *len <= self.data.len() - self.pos)
            .ok_or_else(|| cbor_error("length exceeds the data"))
    }

    fn value(&mut self, depth: usize) -> AppResult<Value> {
        if depth > MAX_DEPTH {
            return Err(cbor_error("nested too deeply"));
        }
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        Ok(match major {
            0 => Value::Int(
                i64::try_from(self.argument(info)?).map_err(|_| cbor_error("integer too large"))?,
            ),
            1 => Value::Int(
                -1 - i64::try_from(self.argument(info)?)
                    .map_err(|_| cbor_error("integer too large"))?,
            ),
            2 => {
                let len = self.length(info)?;
                Value::Bytes(self.take(len)?.to_vec())
            }
            3 => {
                let len = self.length(info)?;
                Value::Text(
                    String::from_utf8(self.take(len)?.to_vec())
                        .map_err(|_| cbor_error("text is not UTF-8"))?,
                )
            }
            4 => {
                let len = self.length(info)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let len = self.length(info)?;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Value::Map(entries)
            }
            // Tags: skip the tag, keep the value.
            6 => {
                self.argument(info)?;
                self.value(depth + 1)?
            }
            7 => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 | 23 => Value::Null,
                _ => return Err(cbor_error("floats and simple values are not supported")),
            },
            _ => unreachable!("major type is three bits"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_rfc_8949_examples() {
        let cases: Vec<(Value, &str)> = vec![
            (Value::Int(0), "00"),
            (Value::Int(23), "17"),
            (Value::Int(24), "1818"),
            (Value::Int(1000), "1903e8"),
            (Value::Int(1_000_000), "1a000f4240"),
            (Value::Int(-1), "20"),
            (Value::Int(-7), "26"),
            (Value::Int(-1000), "3903e7"),
            (Value::Bytes(vec![1, 2, 3, 4]), "4401020304"),
            (Value::text("IETF"), "6449455446"),
            (
                Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
                "83010203",
            ),
            (Value::Bool(true), "f5"),
        ];
        for (value, hex) in cases {
            assert_eq!(hex::encode(value.encode()), hex, "{value:?}");
            assert_eq!(Value::decode(&hex::decode(hex).unwrap()).unwrap(), value);
        }
    }

    #[test]
    fn sorts_map_keys_canonically() {
        // CTAP2 canonical order: by encoded length, then bytewise.
        let map = Value::Map(vec![
            (Value::text("rk"), Value::Bool(false)),
            (Value::Int(10), Value::Int(0)),
            (Value::Int(1), Value::Int(0)),
            (Value::Int(-1), Value::Int(0)),
            (Value::text("a"), Value::Int(0)),
        ]);
        assert_eq!(hex::encode(map.encode()), "a501000a00200061610062726bf4");
    }

    #[test]
    fn rejects_hostile_input() {
        assert!(Value::decode(&[0x5a, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(Value::decode(&[0x9f]).is_err());
        assert!(Value::decode(&[0x81; 40]).is_err());
        assert!(Value::decode(&[0x00, 0x00]).is_err());
        assert!(Value::decode(&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }
}
