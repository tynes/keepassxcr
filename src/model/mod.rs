use std::collections::{BTreeMap, BTreeSet};

use secrecy::SecretString;
use uuid::Uuid;

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
}

/// A group of entries in the database.
#[derive(Debug, Clone)]
pub struct Group {
    uuid: Uuid,
    name: String,
    groups: Vec<Group>,
    entries: Vec<Entry>,
}

impl Group {
    /// Create a new group.
    pub fn new(name: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name,
            groups: Vec::new(),
            entries: Vec::new(),
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
}

/// Database metadata.
#[derive(Debug, Clone)]
pub struct Meta {
    name: String,
    description: String,
}

impl Meta {
    /// Create metadata with a name.
    pub fn new(name: String) -> Self {
        Self {
            name,
            description: String::new(),
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
}

/// In-memory database model.
#[derive(Debug, Clone)]
pub struct Database {
    meta: Meta,
    root: Group,
}

impl Database {
    /// Create a new database with a root group.
    pub fn new(name: String) -> Self {
        Self {
            meta: Meta::new(name.clone()),
            root: Group::new(name),
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
