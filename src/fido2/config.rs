//! Where a database keeps its FIDO2 settings: the KDBX 4 `PublicCustomData`
//! header, an unencrypted variant map that KeePassXC also uses (for its
//! `KPXC_PUBLIC_*` keys) and keeps when it saves.
//!
//! None of it is secret: the credential id is only usable by the device that
//! made it (or a Ledger restored from the same seed), and the salt is useless
//! without the device. Tampering with it gives a wrong key, which the
//! header's HMAC then rejects.

use std::collections::BTreeMap;
use std::io::Cursor;

use crate::crypto::sha256;
use crate::error::{AppError, AppResult};
use crate::fido2::SALT_LEN;
use crate::format::{VariantValue, read_variant_map, write_variant_map};

const KEY_VERSION: &str = "KPXCR_FIDO2_VERSION";
const KEY_RP_ID: &str = "KPXCR_FIDO2_RP_ID";
const KEY_CREDENTIAL_ID: &str = "KPXCR_FIDO2_CREDENTIAL_ID";
const KEY_SALT: &str = "KPXCR_FIDO2_SALT";
const KEYS: [&str; 4] = [KEY_VERSION, KEY_RP_ID, KEY_CREDENTIAL_ID, KEY_SALT];
/// Layout version of the keys above.
const VERSION: u32 = 1;

/// How a database asks its FIDO2 device for the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Fido2Config {
    /// Relying party id the credential was registered under.
    pub rp_id: String,
    /// The device's credential id.
    pub credential_id: Vec<u8>,
    /// Salt the device derives the secret from.
    pub salt: [u8; SALT_LEN],
}

impl std::fmt::Debug for Fido2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fido2Config")
            .field("rp_id", &self.rp_id)
            .field("credential", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Fido2Config {
    /// The settings stored in a `PublicCustomData` header, if any.
    ///
    /// # Errors
    ///
    /// Fails when the header is malformed, or holds incomplete or newer settings.
    pub fn from_public_custom_data(data: Option<&[u8]>) -> AppResult<Option<Self>> {
        let map = read_map(data)?;
        let Some(version) = map.get(KEY_VERSION) else {
            return Ok(None);
        };
        if *version != VariantValue::UInt32(VERSION) {
            return Err(AppError::Fido2(
                "the database's FIDO2 settings come from a newer keepassxcr".to_string(),
            ));
        }
        let incomplete =
            || AppError::Fido2("the database's FIDO2 settings are incomplete".to_string());
        let rp_id = match map.get(KEY_RP_ID) {
            Some(VariantValue::String(rp_id)) => rp_id.clone(),
            _ => return Err(incomplete()),
        };
        let credential_id = match map.get(KEY_CREDENTIAL_ID) {
            Some(VariantValue::ByteArray(id)) if !id.is_empty() => id.clone(),
            _ => return Err(incomplete()),
        };
        let salt = match map.get(KEY_SALT) {
            Some(VariantValue::ByteArray(salt)) => {
                <[u8; SALT_LEN]>::try_from(salt.as_slice()).map_err(|_| incomplete())?
            }
            _ => return Err(incomplete()),
        };
        Ok(Some(Self {
            rp_id,
            credential_id,
            salt,
        }))
    }

    /// `data` with these settings added, replacing any earlier ones and
    /// keeping every other key.
    ///
    /// # Errors
    ///
    /// Fails when `data` is malformed.
    pub fn store(&self, data: Option<&[u8]>) -> AppResult<Vec<u8>> {
        let mut map = read_map(data)?;
        map.insert(KEY_VERSION.to_string(), VariantValue::UInt32(VERSION));
        map.insert(
            KEY_RP_ID.to_string(),
            VariantValue::String(self.rp_id.clone()),
        );
        map.insert(
            KEY_CREDENTIAL_ID.to_string(),
            VariantValue::ByteArray(self.credential_id.clone()),
        );
        map.insert(
            KEY_SALT.to_string(),
            VariantValue::ByteArray(self.salt.to_vec()),
        );
        write_map(&map)
    }

    /// `data` without FIDO2 settings, keeping every other key; `None` when
    /// nothing is left.
    ///
    /// # Errors
    ///
    /// Fails when `data` is malformed.
    pub fn remove(data: Option<&[u8]>) -> AppResult<Option<Vec<u8>>> {
        let mut map = read_map(data)?;
        for key in KEYS {
            map.remove(key);
        }
        if map.is_empty() {
            return Ok(None);
        }
        write_map(&map).map(Some)
    }

    /// A short hex name for the credential, to tell databases apart.
    pub fn fingerprint(&self) -> String {
        hex::encode(&sha256(&self.credential_id)[..4])
    }
}

fn read_map(data: Option<&[u8]>) -> AppResult<BTreeMap<String, VariantValue>> {
    match data {
        Some(bytes) if !bytes.is_empty() => read_variant_map(&mut Cursor::new(bytes)),
        _ => Ok(BTreeMap::new()),
    }
}

fn write_map(map: &BTreeMap<String, VariantValue>) -> AppResult<Vec<u8>> {
    let mut bytes = Vec::new();
    write_variant_map(&mut bytes, map)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Fido2Config {
        Fido2Config {
            rp_id: "keepassxcr".to_string(),
            credential_id: vec![1, 2, 3, 4],
            salt: [9; SALT_LEN],
        }
    }

    #[test]
    fn round_trips_and_keeps_other_keys() {
        let mut theirs = BTreeMap::new();
        theirs.insert(
            "KPXC_PUBLIC_NAME".to_string(),
            VariantValue::String("Vault".to_string()),
        );
        theirs.insert(
            "KPXC_PUBLIC_UUID".to_string(),
            VariantValue::ByteArray(vec![7; 16]),
        );
        let existing = write_map(&theirs).expect("write");

        let stored = config().store(Some(&existing)).expect("store");
        assert_eq!(
            Fido2Config::from_public_custom_data(Some(&stored)).expect("read"),
            Some(config())
        );
        let map = read_map(Some(&stored)).expect("map");
        assert_eq!(map.get("KPXC_PUBLIC_NAME"), theirs.get("KPXC_PUBLIC_NAME"));
        assert_eq!(map.get("KPXC_PUBLIC_UUID"), theirs.get("KPXC_PUBLIC_UUID"));

        let removed = Fido2Config::remove(Some(&stored)).expect("remove");
        assert_eq!(removed, Some(existing));
    }

    #[test]
    fn removing_the_only_keys_leaves_nothing() {
        let stored = config().store(None).expect("store");
        assert_eq!(Fido2Config::remove(Some(&stored)).expect("remove"), None);
        assert_eq!(
            Fido2Config::from_public_custom_data(None).expect("none"),
            None
        );
    }

    #[test]
    fn rejects_incomplete_or_newer_settings() {
        let mut map = read_map(Some(&config().store(None).expect("store"))).expect("map");
        map.remove(KEY_SALT);
        let incomplete = write_map(&map).expect("write");
        assert!(Fido2Config::from_public_custom_data(Some(&incomplete)).is_err());

        map.insert(KEY_VERSION.to_string(), VariantValue::UInt32(VERSION + 1));
        let newer = write_map(&map).expect("write");
        assert!(Fido2Config::from_public_custom_data(Some(&newer)).is_err());
    }
}
