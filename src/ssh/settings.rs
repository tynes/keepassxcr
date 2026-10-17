//! KeeAgent entry settings, the `KeeAgent.settings` attachment KeePassXC and
//! the KeeAgent plugin for KeePass 2 use to mark an entry as an SSH key.

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::error::{AppError, AppResult};
use crate::model::Entry;

/// Name of the attachment that holds the settings.
pub const SETTINGS_ATTACHMENT: &str = "KeeAgent.settings";

/// Where the private key lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyLocation {
    /// An attachment on the same entry, by name.
    Attachment(String),
    /// A file on disk. Relative paths are relative to the database's folder;
    /// `$VAR`, `${VAR}` and a leading `~` are expanded, as in KeePassXC.
    File(String),
}

/// Settings of one entry, with KeePassXC's defaults for missing elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeeAgentSettings {
    /// The entry is an SSH key that may be loaded.
    pub allow_use: bool,
    /// Load the key when the database is unlocked.
    pub add_at_open: bool,
    /// Remove the key when the database is locked.
    pub remove_at_close: bool,
    /// Ask ssh-agent to confirm each use.
    pub confirm: bool,
    /// Have ssh-agent forget the key after [`Self::lifetime_secs`].
    pub use_lifetime: bool,
    /// Lifetime in seconds when [`Self::use_lifetime`] is set.
    pub lifetime_secs: u32,
    /// Location type as written (`attachment` or `file`).
    selected_type: String,
    attachment_name: String,
    save_attachment_to_temp_file: bool,
    file_name: String,
}

impl Default for KeeAgentSettings {
    fn default() -> Self {
        Self {
            allow_use: false,
            add_at_open: false,
            remove_at_close: false,
            confirm: false,
            use_lifetime: false,
            lifetime_secs: 600,
            selected_type: "file".to_string(),
            attachment_name: String::new(),
            save_attachment_to_temp_file: false,
            file_name: String::new(),
        }
    }
}

impl KeeAgentSettings {
    /// Settings that load the key in attachment `name`, with what KeePassXC
    /// turns on when you tick "Add key to agent" plus add on unlock and
    /// remove on lock.
    pub fn for_attachment(name: &str) -> Self {
        Self {
            allow_use: true,
            add_at_open: true,
            remove_at_close: true,
            selected_type: "attachment".to_string(),
            attachment_name: name.to_string(),
            ..Self::default()
        }
    }

    /// The entry's settings, or `None` when it has no settings attachment.
    pub fn from_entry(entry: &Entry) -> Option<AppResult<Self>> {
        entry
            .attachments()
            .iter()
            .find(|attachment| attachment.name() == SETTINGS_ATTACHMENT)
            .map(|attachment| Self::from_xml(attachment.data()))
    }

    /// Where the private key is.
    pub fn location(&self) -> AppResult<KeyLocation> {
        if self.selected_type == "attachment" {
            if self.attachment_name.is_empty() {
                return Err(invalid("no private key attachment is selected"));
            }
            Ok(KeyLocation::Attachment(self.attachment_name.clone()))
        } else {
            if self.file_name.is_empty() {
                return Err(invalid("no private key file is selected"));
            }
            Ok(KeyLocation::File(self.file_name.clone()))
        }
    }

    /// Parse the settings XML, which KeePassXC writes as UTF-16 with a BOM.
    /// Unknown elements are skipped, like KeePassXC does.
    pub fn from_xml(data: &[u8]) -> AppResult<Self> {
        let text = decode_text(data)?;
        let mut reader = Reader::from_str(&text);
        let mut settings = Self::default();
        let mut path: Vec<String> = Vec::new();
        let mut value = String::new();
        let mut seen_root = false;
        loop {
            match reader.read_event() {
                Ok(Event::Start(element)) => {
                    let name = element.name().0.to_string();
                    if path.is_empty() {
                        if name != "EntrySettings" {
                            return Err(invalid("invalid KeeAgent settings file structure"));
                        }
                        seen_root = true;
                    }
                    path.push(name);
                    value.clear();
                }
                Ok(Event::Empty(element)) => {
                    let name = element.name().0.to_string();
                    if path.is_empty() {
                        if name != "EntrySettings" {
                            return Err(invalid("invalid KeeAgent settings file structure"));
                        }
                        seen_root = true;
                        break;
                    }
                    path.push(name);
                    settings.set(&path, "");
                    path.pop();
                }
                Ok(Event::Text(text)) => value.push_str(&text.xml10_content()),
                Ok(Event::GeneralRef(reference)) => {
                    value.push(crate::xml::resolve_reference(&reference)?);
                }
                Ok(Event::CData(data)) => value.push_str(&data.into_inner()),
                Ok(Event::End(_)) => {
                    settings.set(&path, &value);
                    value.clear();
                    path.pop();
                    if path.is_empty() {
                        break;
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(err) => return Err(invalid(&format!("bad KeeAgent settings: {err}"))),
            }
        }
        if !seen_root {
            return Err(invalid("invalid KeeAgent settings file structure"));
        }
        Ok(settings)
    }

    /// Apply the text of the element at `path` (from the root down).
    fn set(&mut self, path: &[String], value: &str) {
        let names: Vec<&str> = path.iter().map(String::as_str).collect();
        match names.as_slice() {
            ["EntrySettings", "AllowUseOfSshKey"] => self.allow_use = parse_bool(value),
            ["EntrySettings", "AddAtDatabaseOpen"] => self.add_at_open = parse_bool(value),
            ["EntrySettings", "RemoveAtDatabaseClose"] => self.remove_at_close = parse_bool(value),
            ["EntrySettings", "UseConfirmConstraintWhenAdding"] => self.confirm = parse_bool(value),
            ["EntrySettings", "UseLifetimeConstraintWhenAdding"] => {
                self.use_lifetime = parse_bool(value);
            }
            ["EntrySettings", "LifetimeConstraintDuration"] => {
                // Like Qt's toInt(): anything unparsable is 0.
                self.lifetime_secs = value.trim().parse().unwrap_or(0);
            }
            ["EntrySettings", "Location", "SelectedType"] => self.selected_type = value.to_string(),
            ["EntrySettings", "Location", "AttachmentName"] => {
                self.attachment_name = value.to_string();
            }
            ["EntrySettings", "Location", "SaveAttachmentToTempFile"] => {
                self.save_attachment_to_temp_file = parse_bool(value);
            }
            ["EntrySettings", "Location", "FileName"] => self.file_name = value.to_string(),
            _ => {}
        }
    }

    /// Serialize like KeePassXC 2.7: UTF-16LE with a BOM (KeeAgent itself only
    /// reads UTF-16), two-space indentation.
    pub fn to_xml(&self) -> Vec<u8> {
        let bool_text = |value: bool| if value { "true" } else { "false" };
        let element = |name: &str, value: &str| {
            if value.is_empty() {
                format!("<{name}/>")
            } else {
                format!("<{name}>{}</{name}>", escape(value))
            }
        };
        let lines = [
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>".to_string(),
            "<EntrySettings xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" \
             xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
                .to_string(),
            format!(
                "  <AllowUseOfSshKey>{}</AllowUseOfSshKey>",
                bool_text(self.allow_use)
            ),
            format!(
                "  <AddAtDatabaseOpen>{}</AddAtDatabaseOpen>",
                bool_text(self.add_at_open)
            ),
            format!(
                "  <RemoveAtDatabaseClose>{}</RemoveAtDatabaseClose>",
                bool_text(self.remove_at_close)
            ),
            format!(
                "  <UseConfirmConstraintWhenAdding>{}</UseConfirmConstraintWhenAdding>",
                bool_text(self.confirm)
            ),
            format!(
                "  <UseLifetimeConstraintWhenAdding>{}</UseLifetimeConstraintWhenAdding>",
                bool_text(self.use_lifetime)
            ),
            format!(
                "  <LifetimeConstraintDuration>{}</LifetimeConstraintDuration>",
                self.lifetime_secs
            ),
            "  <Location>".to_string(),
            format!(
                "    <SelectedType>{}</SelectedType>",
                escape(&self.selected_type)
            ),
            format!("    {}", element("AttachmentName", &self.attachment_name)),
            format!(
                "    <SaveAttachmentToTempFile>{}</SaveAttachmentToTempFile>",
                bool_text(self.save_attachment_to_temp_file)
            ),
            format!("    {}", element("FileName", &self.file_name)),
            "  </Location>".to_string(),
            "</EntrySettings>".to_string(),
        ];
        let text = lines.join("\n") + "\n";
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }
}

fn parse_bool(value: &str) -> bool {
    // Qt reads anything starting with "t" (any case) as true.
    value
        .trim_start()
        .chars()
        .next()
        .is_some_and(|ch| ch.eq_ignore_ascii_case(&'t'))
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Decode UTF-16 (with or without a BOM) or UTF-8.
fn decode_text(data: &[u8]) -> AppResult<String> {
    let utf16 = |bytes: &[u8], little: bool| -> AppResult<String> {
        // `as_chunks` splits into 2-byte arrays plus any odd byte left over.
        let (pairs, rest) = bytes.as_chunks::<2>();
        if !rest.is_empty() {
            return Err(invalid("KeeAgent settings are not valid UTF-16"));
        }
        let units = pairs.iter().map(|&pair| {
            if little {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            }
        });
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| invalid("KeeAgent settings are not valid UTF-16"))
    };
    match data {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, true),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, false),
        [0xEF, 0xBB, 0xBF, rest @ ..] => utf8(rest),
        [b'<', 0, ..] => utf16(data, true),
        [0, b'<', ..] => utf16(data, false),
        _ => utf8(data),
    }
}

fn utf8(data: &[u8]) -> AppResult<String> {
    String::from_utf8(data.to_vec()).map_err(|_| invalid("KeeAgent settings are not valid UTF-8"))
}

fn invalid(message: &str) -> AppError {
    AppError::InvalidInput(message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Written by KeePassXC 2.7 for an attachment key (UTF-16LE with BOM).
    fn keepassxc_xml() -> Vec<u8> {
        let text = [
            r#"<?xml version="1.0" encoding="UTF-16"?>"#,
            r#"<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">"#,
            "  <AllowUseOfSshKey>true</AllowUseOfSshKey>",
            "  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>",
            "  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>",
            "  <UseConfirmConstraintWhenAdding>false</UseConfirmConstraintWhenAdding>",
            "  <UseLifetimeConstraintWhenAdding>true</UseLifetimeConstraintWhenAdding>",
            "  <LifetimeConstraintDuration>3600</LifetimeConstraintDuration>",
            "  <Location>",
            "    <SelectedType>attachment</SelectedType>",
            "    <AttachmentName>id_ed25519</AttachmentName>",
            "    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>",
            "    <FileName/>",
            "  </Location>",
            "</EntrySettings>",
            "",
        ]
        .join("\n");
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn reads_keepassxc_settings() {
        let settings = KeeAgentSettings::from_xml(&keepassxc_xml()).unwrap();
        assert!(settings.allow_use && settings.add_at_open && settings.remove_at_close);
        assert!(!settings.confirm);
        assert!(settings.use_lifetime);
        assert_eq!(settings.lifetime_secs, 3600);
        assert_eq!(
            settings.location().unwrap(),
            KeyLocation::Attachment("id_ed25519".to_string())
        );
    }

    #[test]
    fn writes_what_keepassxc_writes() {
        let mut settings = KeeAgentSettings::for_attachment("id_ed25519");
        settings.use_lifetime = true;
        settings.lifetime_secs = 3600;
        assert_eq!(settings.to_xml(), keepassxc_xml());
        assert_eq!(
            KeeAgentSettings::from_xml(&settings.to_xml()).unwrap(),
            settings
        );
    }

    #[test]
    fn reads_utf8_file_location_and_skips_unknown_elements() {
        let xml = b"<EntrySettings><AllowUseOfSshKey>True</AllowUseOfSshKey>\
<Extra><Nested>x</Nested></Extra>\
<Location><SelectedType>file</SelectedType><FileName>~/.ssh/a &amp; b</FileName></Location>\
</EntrySettings>";
        let settings = KeeAgentSettings::from_xml(xml).unwrap();
        assert!(settings.allow_use);
        assert!(!settings.add_at_open);
        assert_eq!(settings.lifetime_secs, 600);
        assert_eq!(
            settings.location().unwrap(),
            KeyLocation::File("~/.ssh/a & b".to_string())
        );
    }

    #[test]
    fn rejects_other_documents() {
        assert!(KeeAgentSettings::from_xml(b"<Other/>").is_err());
        assert!(KeeAgentSettings::from_xml(b"not xml").is_err());
        assert!(KeeAgentSettings::from_xml(&[0xFF, 0xFE, 0x3C]).is_err());
    }
}
