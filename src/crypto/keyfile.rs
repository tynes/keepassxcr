use std::fs;
use std::path::Path;

use base64::Engine as _;
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::crypto::hash::sha256;
use crate::error::{AppError, AppResult};

/// Parsed key file data.
#[derive(Debug, Clone)]
pub struct KeyFile {
    raw_key: Vec<u8>,
}

impl KeyFile {
    /// Load a key file from disk.
    pub fn load(path: &Path) -> AppResult<Self> {
        let data = fs::read(path)?;
        let raw_key = parse_keyfile(&data)?;
        Ok(Self { raw_key })
    }

    /// Raw key bytes.
    pub fn raw_key(&self) -> &[u8] {
        &self.raw_key
    }
}

fn parse_keyfile(data: &[u8]) -> AppResult<Vec<u8>> {
    if let Some(raw) = parse_xml_keyfile(data)? {
        return Ok(raw);
    }

    if data.len() == 32 {
        return Ok(data.to_vec());
    }

    if data.len() == 64 {
        let hex_str = std::str::from_utf8(data)
            .map_err(|_| AppError::Crypto("key file is not valid UTF-8".to_string()))?;
        if hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            let decoded = hex::decode(hex_str)
                .map_err(|_| AppError::Crypto("invalid hex key file".to_string()))?;
            if decoded.len() == 32 {
                return Ok(decoded);
            }
        }
    }

    Ok(sha256(data).to_vec())
}

fn parse_xml_keyfile(data: &[u8]) -> AppResult<Option<Vec<u8>>> {
    let mut reader = Reader::from_reader(data);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut in_data = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Data" => {
                in_data = true;
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"Data" => {
                in_data = false;
            }
            Ok(Event::Text(e)) if in_data => {
                let text = e
                    .unescape()
                    .map_err(|_| AppError::Crypto("invalid XML key file".to_string()))?;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(text.as_bytes())
                    .map_err(|_| AppError::Crypto("invalid base64 in key file".to_string()))?;
                return Ok(Some(decoded));
            }
            Ok(Event::Eof) => break,
            Err(_) => return Ok(None),
            _ => {}
        }
        buf.clear();
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_hash_fallback() {
        let data = b"random";
        let parsed = parse_keyfile(data).expect("parse should work");
        assert_eq!(parsed.len(), 32);
    }

    #[test]
    fn keyfile_xml() {
        let xml = b"<KeyFile><Key><Data>QUJDREVGR0hJSktMTU5PUA==</Data></Key></KeyFile>";
        let parsed = parse_keyfile(xml).expect("parse should work");
        assert_eq!(parsed, b"ABCDEFGHIJKLMNOP".to_vec());
    }
}
