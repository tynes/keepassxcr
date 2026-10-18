use std::fs;
use std::path::Path;

use base64::Engine as _;
use quick_xml::Reader;
use quick_xml::events::Event;

use zeroize::Zeroizing;

use crate::crypto::hash::sha256;
use crate::error::{AppError, AppResult};

/// Parsed key file data, wiped when dropped.
#[derive(Clone)]
pub struct KeyFile {
    raw_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFile").finish_non_exhaustive()
    }
}

impl KeyFile {
    /// Load a key file from disk.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read, is a malformed XML key file, or is
    /// a FIDO2-protected key file, which [`crate::fido2::load_key_file`] opens.
    pub fn load(path: &Path) -> AppResult<Self> {
        let data = Zeroizing::new(fs::read(path)?);
        if crate::fido2::WrappedKeyFile::parse(&data).is_some() {
            return Err(AppError::InvalidInput(format!(
                "{} is protected by a FIDO2 security key; open it with fido2::load_key_file",
                path.display()
            )));
        }
        Self::from_bytes(&data)
    }

    /// A key file from its contents, in any format KeePassXC accepts.
    ///
    /// # Errors
    ///
    /// Fails for a malformed XML key file.
    pub fn from_bytes(data: &[u8]) -> AppResult<Self> {
        let raw_key = Zeroizing::new(parse_keyfile(data)?);
        Ok(Self { raw_key })
    }

    /// A new random key file in KeePassXC's XML format 2.0 (`.keyx`), as
    /// KeePassXC's "Generate" button writes it.
    pub fn generate_xml() -> Zeroizing<Vec<u8>> {
        use rand::RngCore;
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut key[..]);
        let hex = Zeroizing::new(hex::encode_upper(&key[..]));
        let check = hex::encode_upper(&sha256(&key[..])[..4]);
        let groups: Vec<&str> = (0..8).map(|i| &hex[i * 8..i * 8 + 8]).collect();
        let text = Zeroizing::new(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <KeyFile>\n    <Meta>\n        <Version>2.0</Version>\n    </Meta>\n    <Key>\n        \
                 <Data Hash=\"{check}\">\n            {}\n            {}\n        </Data>\n    \
                 </Key>\n</KeyFile>\n",
            groups[..4].join(" "),
            groups[4..].join(" "),
        ));
        Zeroizing::new(text.as_bytes().to_vec())
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

/// Parse a KeePass XML key file.
///
/// Version 1.0 stores the key as base64. Version 2.0 (written by KeePassXC 2.7+
/// and KeePass 2.47+) stores it as whitespace-grouped hex with a `Hash`
/// attribute holding the first 4 bytes of the key's SHA-256 as a checksum.
/// Returns `Ok(None)` when the data is not an XML key file.
fn parse_xml_keyfile(data: &[u8]) -> AppResult<Option<Vec<u8>>> {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut in_version = false;
    let mut in_data = false;
    let mut version = String::new();
    let mut hash_attr = None;
    let mut key_text = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().0 == "Version" => in_version = true,
            Ok(Event::Start(ref e)) if e.name().0 == "Data" => {
                in_data = true;
                hash_attr = e
                    .attributes()
                    .flatten()
                    .find(|attr| attr.key.0 == "Hash")
                    .map(|attr| attr.value.into_owned());
            }
            Ok(Event::End(ref e)) if e.name().0 == "Version" => in_version = false,
            Ok(Event::End(ref e)) if e.name().0 == "Data" => in_data = false,
            Ok(Event::Text(e)) if in_version || in_data => {
                // Base64 and hex never contain entity references, so the
                // text needs no unescaping.
                let text = e.xml10_content().into_owned();
                if in_version {
                    version = text;
                } else {
                    key_text = Some(text);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Ok(None),
            _ => {}
        }
        buf.clear();
    }

    let Some(key_text) = key_text else {
        return Ok(None);
    };

    if version.trim() == "2.0" {
        let hex_text: String = key_text.chars().filter(|c| !c.is_whitespace()).collect();
        let key = hex::decode(&hex_text)
            .map_err(|_| AppError::Crypto("invalid hex in key file".to_string()))?;
        if let Some(expected) = hash_attr {
            let expected = hex::decode(expected.trim())
                .map_err(|_| AppError::Crypto("invalid key file hash".to_string()))?;
            if sha256(&key)[..4] != expected[..] {
                return Err(AppError::Crypto(
                    "key file checksum mismatch; the key file may be corrupt".to_string(),
                ));
            }
        }
        return Ok(Some(key));
    }

    let key = base64::engine::general_purpose::STANDARD
        .decode(key_text.trim().as_bytes())
        .map_err(|_| AppError::Crypto("invalid base64 in key file".to_string()))?;
    Ok(Some(key))
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
    fn keyfile_xml_v2() {
        // Key file generated by keepassxc-cli 2.7.6.
        let xml = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<KeyFile><Meta><Version>2.0</Version></Meta><Key>
<Data Hash=\"15026749\">
    A462079F B4029D8A D63F30DD 0BB7B905
    D32F77BF 1C7223A2 47F7FA68 AA2017D9
</Data></Key></KeyFile>";
        let parsed = parse_keyfile(xml).expect("parse should work");
        assert_eq!(
            hex::encode_upper(parsed),
            "A462079FB4029D8AD63F30DD0BB7B905D32F77BF1C7223A247F7FA68AA2017D9"
        );
    }

    #[test]
    fn keyfile_xml_v2_bad_checksum() {
        let xml = b"<KeyFile><Meta><Version>2.0</Version></Meta><Key>
<Data Hash=\"00000000\">A462079FB4029D8AD63F30DD0BB7B905D32F77BF1C7223A247F7FA68AA2017D9</Data>
</Key></KeyFile>";
        assert!(parse_keyfile(xml).is_err());
    }

    #[test]
    fn keyfile_xml() {
        let xml = b"<KeyFile><Key><Data>QUJDREVGR0hJSktMTU5PUA==</Data></Key></KeyFile>";
        let parsed = parse_keyfile(xml).expect("parse should work");
        assert_eq!(parsed, b"ABCDEFGHIJKLMNOP".to_vec());
    }
}
