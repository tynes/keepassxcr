use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use secrecy::SecretString;
use time::OffsetDateTime;
use uuid::Uuid;

/// Maximum number of history items kept per entry (the KeePassXC default).
pub const HISTORY_MAX_ITEMS: usize = 10;

/// Seconds between 0001-01-01T00:00:00Z and the Unix epoch.
pub const SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH: i64 = 62_135_596_800;

/// Parse a KDBX timestamp into seconds since 0001-01-01 UTC.
///
/// KDBX4 stores little-endian seconds encoded as base64; KDBX3 (and some
/// writers of KDBX4) use ISO 8601 text.
pub fn parse_kdbx_time(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.contains('-') || text.contains(':') {
        let parsed =
            OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339).ok()?;
        return Some(parsed.unix_timestamp() + SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .ok()?;
    let array: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(i64::from_le_bytes(array))
}

/// Return the text of the first `<tag>…</tag>` inside an XML snippet.
fn element_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    Some(&xml[start..end])
}

/// An XML element keepassxcr does not interpret (for example `Times`, `Tags`,
/// `AutoType` or `CustomData`).
///
/// It is kept verbatim so that saving a database written by KeePassXC does not
/// drop data. It never contains protected (inner-stream encrypted) values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawElement {
    name: String,
    xml: String,
}

impl RawElement {
    /// Wrap the serialized XML of an element named `name`.
    pub fn new(name: String, xml: String) -> Self {
        Self { name, xml }
    }

    /// Element name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Serialized element, including its start and end tags.
    pub fn xml(&self) -> &str {
        &self.xml
    }
}

/// Attachment data stored with an entry.
#[derive(Debug, Clone)]
pub struct Attachment {
    name: String,
    data: Vec<u8>,
}

impl Attachment {
    /// Create a new attachment.
    pub fn new(name: String, data: Vec<u8>) -> Self {
        Self { name, data }
    }

    /// Attachment name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Attachment bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Entry fields supported by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryField {
    /// Entry title.
    Title,
    /// Entry username.
    Username,
    /// Entry password.
    Password,
    /// Entry URL.
    Url,
    /// Entry notes.
    Notes,
}

/// A database entry.
#[derive(Debug, Clone)]
pub struct Entry {
    uuid: Uuid,
    title: String,
    username: String,
    password: SecretString,
    url: String,
    notes: String,
    custom_fields: BTreeMap<String, String>,
    protected_fields: BTreeSet<String>,
    attachments: Vec<Attachment>,
    extra: Vec<RawElement>,
    history: Vec<Entry>,
    modified: Option<OffsetDateTime>,
}

impl Entry {
    /// Create a new entry with default fields.
    pub fn new(title: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            title,
            username: String::new(),
            password: SecretString::new(String::new()),
            url: String::new(),
            notes: String::new(),
            custom_fields: BTreeMap::new(),
            protected_fields: BTreeSet::new(),
            attachments: Vec::new(),
            extra: Vec::new(),
            history: Vec::new(),
            modified: None,
        }
    }

    /// Create a new entry with a specific UUID.
    pub fn with_uuid(uuid: Uuid, title: String) -> Self {
        Self {
            uuid,
            ..Self::new(title)
        }
    }

    /// Entry UUID.
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// Replace the entry UUID (used when parsing).
    pub fn set_uuid(&mut self, uuid: Uuid) {
        self.uuid = uuid;
    }

    /// Entry title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Update entry title.
    pub fn set_title(&mut self, title: String) {
        self.title = title;
    }

    /// Entry username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Update entry username.
    pub fn set_username(&mut self, username: String) {
        self.username = username;
    }

    /// Entry password.
    pub fn password(&self) -> &SecretString {
        &self.password
    }

    /// Update entry password.
    pub fn set_password(&mut self, password: SecretString) {
        self.password = password;
        self.protected_fields.insert("Password".to_string());
    }

    /// Entry URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Update entry URL.
    pub fn set_url(&mut self, url: String) {
        self.url = url;
    }

    /// Entry notes.
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// Update entry notes.
    pub fn set_notes(&mut self, notes: String) {
        self.notes = notes;
    }

    /// Set a custom field value.
    pub fn set_custom_field(&mut self, key: String, value: String, protected: bool) {
        self.custom_fields.insert(key.clone(), value);
        if protected {
            self.protected_fields.insert(key);
        }
    }

    /// Return custom fields.
    pub fn custom_fields(&self) -> &BTreeMap<String, String> {
        &self.custom_fields
    }

    /// Return the set of protected field names.
    pub fn protected_fields(&self) -> &BTreeSet<String> {
        &self.protected_fields
    }

    /// Entry attachments.
    pub fn attachments(&self) -> &[Attachment] {
        &self.attachments
    }

    /// Mutable access to attachments.
    pub fn attachments_mut(&mut self) -> &mut Vec<Attachment> {
        &mut self.attachments
    }

    /// Uninterpreted XML elements preserved from the source file.
    pub fn extra(&self) -> &[RawElement] {
        &self.extra
    }

    /// Mutable access to preserved XML elements.
    pub fn extra_mut(&mut self) -> &mut Vec<RawElement> {
        &mut self.extra
    }

    /// Previous versions of this entry, oldest first.
    pub fn history(&self) -> &[Entry] {
        &self.history
    }

    /// Mutable access to the entry history.
    pub fn history_mut(&mut self) -> &mut Vec<Entry> {
        &mut self.history
    }

    /// Modification time set in this session, if the entry was changed.
    pub fn modified(&self) -> Option<OffsetDateTime> {
        self.modified
    }

    /// Last modification time as seconds since 0001-01-01 UTC, if known.
    ///
    /// Uses the time set by [`Entry::begin_update`] in this session, otherwise the
    /// `LastModificationTime` from the preserved `Times` element. Both the KDBX4
    /// (base64 seconds) and KDBX3 (ISO 8601) encodings are understood.
    pub fn last_modification_secs(&self) -> Option<i64> {
        if let Some(modified) = self.modified {
            return Some(modified.unix_timestamp() + SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH);
        }
        let times = self.extra.iter().find(|raw| raw.name() == "Times")?;
        let text = element_text(times.xml(), "LastModificationTime")?;
        parse_kdbx_time(text)
    }

    /// Record the current state in the history and mark the entry as modified now.
    ///
    /// Call this before changing an existing entry, like KeePassXC does, so the
    /// previous password and fields stay recoverable. The history is capped at
    /// [`HISTORY_MAX_ITEMS`], dropping the oldest items first.
    pub fn begin_update(&mut self) {
        let mut snapshot = self.clone();
        snapshot.history.clear();
        self.history.push(snapshot);
        if self.history.len() > HISTORY_MAX_ITEMS {
            let excess = self.history.len() - HISTORY_MAX_ITEMS;
            self.history.drain(..excess);
        }
        self.modified = Some(OffsetDateTime::now_utc());
    }
}

/// A group of entries in the database.
#[derive(Debug, Clone)]
pub struct Group {
    uuid: Uuid,
    name: String,
    groups: Vec<Group>,
    entries: Vec<Entry>,
    extra: Vec<RawElement>,
}

impl Group {
    /// Create a new group.
    pub fn new(name: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name,
            groups: Vec::new(),
            entries: Vec::new(),
            extra: Vec::new(),
        }
    }

    /// Create a new group with a specific UUID.
    pub fn with_uuid(uuid: Uuid, name: String) -> Self {
        Self {
            uuid,
            ..Self::new(name)
        }
    }

    /// Group UUID.
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// Replace the group UUID (used when parsing).
    pub fn set_uuid(&mut self, uuid: Uuid) {
        self.uuid = uuid;
    }

    /// Group name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set group name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Child groups.
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// Mutable child groups.
    pub fn groups_mut(&mut self) -> &mut Vec<Group> {
        &mut self.groups
    }

    /// Entries in this group.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Mutable entries in this group.
    pub fn entries_mut(&mut self) -> &mut Vec<Entry> {
        &mut self.entries
    }

    /// Find a child group by name.
    pub fn find_group_mut(&mut self, name: &str) -> Option<&mut Group> {
        self.groups.iter_mut().find(|group| group.name == name)
    }

    /// Find a child group by name.
    pub fn find_group(&self, name: &str) -> Option<&Group> {
        self.groups.iter().find(|group| group.name == name)
    }

    /// Find an entry by title.
    pub fn find_entry_mut(&mut self, title: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|entry| entry.title() == title)
    }

    /// Find an entry by title.
    pub fn find_entry(&self, title: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.title() == title)
    }

    /// Uninterpreted XML elements preserved from the source file.
    pub fn extra(&self) -> &[RawElement] {
        &self.extra
    }

    /// Mutable access to preserved XML elements.
    pub fn extra_mut(&mut self) -> &mut Vec<RawElement> {
        &mut self.extra
    }

    /// Find this group or a descendant by UUID.
    pub fn group_by_uuid(&self, uuid: Uuid) -> Option<&Group> {
        if self.uuid == uuid {
            return Some(self);
        }
        self.groups
            .iter()
            .find_map(|child| child.group_by_uuid(uuid))
    }

    /// Find this group or a descendant by UUID.
    pub fn group_by_uuid_mut(&mut self, uuid: Uuid) -> Option<&mut Group> {
        if self.uuid == uuid {
            return Some(self);
        }
        self.groups
            .iter_mut()
            .find_map(|child| child.group_by_uuid_mut(uuid))
    }

    /// Find an entry in this group or a descendant by UUID.
    pub fn entry_by_uuid_mut(&mut self, uuid: Uuid) -> Option<&mut Entry> {
        if let Some(index) = self.entries.iter().position(|entry| entry.uuid == uuid) {
            return Some(&mut self.entries[index]);
        }
        self.groups
            .iter_mut()
            .find_map(|child| child.entry_by_uuid_mut(uuid))
    }

    /// Copy of this group's own data (UUID, name, preserved XML) without children.
    pub fn shell(&self) -> Group {
        Group {
            uuid: self.uuid,
            name: self.name.clone(),
            groups: Vec::new(),
            entries: Vec::new(),
            extra: self.extra.clone(),
        }
    }
}

/// Database metadata.
#[derive(Debug, Clone)]
pub struct Meta {
    name: String,
    description: String,
    extra: Vec<RawElement>,
}

impl Meta {
    /// Create metadata with a name.
    pub fn new(name: String) -> Self {
        Self {
            name,
            description: String::new(),
            extra: Vec::new(),
        }
    }

    /// Database name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Update database name.
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Database description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Update database description.
    pub fn set_description(&mut self, description: String) {
        self.description = description;
    }

    /// Uninterpreted metadata elements preserved from the source file.
    pub fn extra(&self) -> &[RawElement] {
        &self.extra
    }

    /// Mutable access to preserved metadata elements.
    pub fn extra_mut(&mut self) -> &mut Vec<RawElement> {
        &mut self.extra
    }
}

/// In-memory database model.
#[derive(Debug, Clone)]
pub struct Database {
    meta: Meta,
    root: Group,
    root_extra: Vec<RawElement>,
}

impl Database {
    /// Create a new database with a root group.
    pub fn new(name: String) -> Self {
        Self {
            meta: Meta::new(name.clone()),
            root: Group::new(name),
            root_extra: Vec::new(),
        }
    }

    /// Metadata for the database.
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Mutable metadata.
    pub fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }

    /// Root group.
    pub fn root(&self) -> &Group {
        &self.root
    }

    /// Mutable root group.
    pub fn root_mut(&mut self) -> &mut Group {
        &mut self.root
    }

    /// Uninterpreted `Root` children preserved from the source file
    /// (for example `DeletedObjects`).
    pub fn root_extra(&self) -> &[RawElement] {
        &self.root_extra
    }

    /// Mutable access to preserved `Root` children.
    pub fn root_extra_mut(&mut self) -> &mut Vec<RawElement> {
        &mut self.root_extra
    }

    /// Find a group by path.
    pub fn group_by_path_mut(&mut self, path: &[&str]) -> Option<&mut Group> {
        let mut current = &mut self.root;
        for segment in path {
            let next = current.find_group_mut(segment)?;
            current = next;
        }
        Some(current)
    }

    /// Find a group by path.
    pub fn group_by_path(&self, path: &[&str]) -> Option<&Group> {
        let mut current = &self.root;
        for segment in path {
            let next = current.find_group(segment)?;
            current = next;
        }
        Some(current)
    }

    /// Find an entry by path.
    pub fn entry_by_path_mut(&mut self, group_path: &[&str], title: &str) -> Option<&mut Entry> {
        let group = self.group_by_path_mut(group_path)?;
        group.find_entry_mut(title)
    }

    /// Find an entry by path.
    pub fn entry_by_path(&self, group_path: &[&str], title: &str) -> Option<&Entry> {
        let group = self.group_by_path(group_path)?;
        group.find_entry(title)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn attachment_roundtrip() {
        let attachment = Attachment::new("file".to_string(), vec![1, 2, 3]);
        assert_eq!(attachment.name(), "file");
        assert_eq!(attachment.data(), &[1, 2, 3]);
    }

    #[test]
    fn entry_fields_update() {
        let mut entry = Entry::new("Title".to_string());
        entry.set_username("user".to_string());
        entry.set_url("https://example.com".to_string());
        entry.set_notes("notes".to_string());
        entry.set_custom_field("key".to_string(), "value".to_string(), true);

        assert_eq!(entry.title(), "Title");
        assert_eq!(entry.username(), "user");
        assert_eq!(entry.url(), "https://example.com");
        assert_eq!(entry.notes(), "notes");
        assert_eq!(entry.custom_fields().get("key"), Some(&"value".to_string()));
        assert!(entry.protected_fields().contains("key"));
    }

    #[test]
    fn group_finders() {
        let mut root = Group::new("Root".to_string());
        root.groups_mut().push(Group::new("Child".to_string()));
        root.entries_mut().push(Entry::new("Entry".to_string()));

        assert!(root.find_group("Child").is_some());
        assert!(root.find_entry("Entry").is_some());
    }

    #[test]
    fn entry_with_uuid() {
        let uuid = Uuid::new_v4();
        let entry = Entry::with_uuid(uuid, "Title".to_string());
        assert_eq!(entry.uuid(), uuid);
    }

    #[test]
    fn parses_both_time_encodings() {
        // 2024-01-01T00:00:00Z in both encodings.
        let iso = parse_kdbx_time("2024-01-01T00:00:00Z").expect("iso");
        let secs: i64 = 1_704_067_200 + SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH;
        let b64 = base64::engine::general_purpose::STANDARD.encode(secs.to_le_bytes());
        assert_eq!(iso, secs);
        assert_eq!(parse_kdbx_time(&b64), Some(secs));
    }

    #[test]
    fn begin_update_keeps_previous_version() {
        let mut entry = Entry::new("Title".to_string());
        entry.set_password(SecretString::new("old".to_string()));
        entry.begin_update();
        entry.set_password(SecretString::new("new".to_string()));

        assert_eq!(entry.history().len(), 1);
        assert_eq!(entry.history()[0].password().expose_secret(), "old");
        assert!(entry.modified().is_some());
    }

    #[test]
    fn begin_update_caps_history() {
        let mut entry = Entry::new("Title".to_string());
        for _ in 0..(HISTORY_MAX_ITEMS + 5) {
            entry.begin_update();
        }
        assert_eq!(entry.history().len(), HISTORY_MAX_ITEMS);
    }

    #[test]
    fn group_with_uuid() {
        let uuid = Uuid::new_v4();
        let group = Group::with_uuid(uuid, "Group".to_string());
        assert_eq!(group.uuid(), uuid);
    }

    #[test]
    fn database_paths() {
        let mut db = Database::new("Root".to_string());
        db.root_mut()
            .groups_mut()
            .push(Group::new("Group".to_string()));
        let group_path = vec!["Group"];
        assert!(db.group_by_path(&group_path).is_some());
    }
}
