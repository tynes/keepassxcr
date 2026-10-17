pub mod merge;
pub mod placeholders;
pub mod times;

use std::collections::{BTreeMap, BTreeSet};

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use times::{SECONDS_FROM_YEAR_1_TO_UNIX_EPOCH, Times, Timestamp};

/// History items kept per entry when the database does not say (KeePassXC's default).
pub const DEFAULT_HISTORY_MAX_ITEMS: i32 = 10;
/// Total history size per entry when the database does not say (KeePassXC's default).
pub const DEFAULT_HISTORY_MAX_SIZE: i64 = 6 * 1024 * 1024;
/// Icon KeePassXC gives the recycle bin group.
const RECYCLE_BIN_ICON: u32 = 43;

/// How much history an entry keeps, from the database settings. A negative
/// value means no limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryLimits {
    /// Most history items per entry.
    pub max_items: i32,
    /// Most bytes of history per entry, as [`Entry::size`] counts them.
    pub max_size: i64,
}

impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            max_items: DEFAULT_HISTORY_MAX_ITEMS,
            max_size: DEFAULT_HISTORY_MAX_SIZE,
        }
    }
}

/// Return the text of the first `<tag>…</tag>` inside an XML snippet.
pub(crate) fn element_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
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

/// Attachment data stored with an entry. The bytes are wiped when dropped.
#[derive(Clone)]
pub struct Attachment {
    name: String,
    data: Zeroizing<Vec<u8>>,
    protected: bool,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("len", &self.data.len())
            .field("protected", &self.protected)
            .finish()
    }
}

impl Attachment {
    /// Create a new attachment, protected in memory like KeePassXC's.
    pub fn new(name: String, data: Vec<u8>) -> Self {
        Self::with_protection(name, data, true)
    }

    /// Create an attachment with an explicit memory-protection flag (the
    /// flag byte of a KDBX 4 inner-header binary, or `Protected` in KDBX 3.1).
    pub fn with_protection(name: String, data: Vec<u8>, protected: bool) -> Self {
        Self {
            name,
            data: Zeroizing::new(data),
            protected,
        }
    }

    /// Whether the attachment is marked for in-memory protection.
    pub fn protected(&self) -> bool {
        self.protected
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

/// A database entry. Field values are wiped from memory when dropped.
#[derive(Clone)]
pub struct Entry {
    uuid: Uuid,
    title: Zeroizing<String>,
    username: Zeroizing<String>,
    password: SecretString,
    url: Zeroizing<String>,
    notes: Zeroizing<String>,
    custom_fields: BTreeMap<String, Zeroizing<String>>,
    protected_fields: BTreeSet<String>,
    attachments: Vec<Attachment>,
    tags: Vec<String>,
    times: Times,
    previous_parent_group: Option<Uuid>,
    extra: Vec<RawElement>,
    history: Vec<Entry>,
}

impl std::fmt::Debug for Entry {
    /// Shows the structure only: field values may be secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("uuid", &self.uuid)
            .field(
                "custom_fields",
                &self.custom_fields.keys().collect::<Vec<_>>(),
            )
            .field("attachments", &self.attachments)
            .field("history", &self.history.len())
            .finish_non_exhaustive()
    }
}

impl Entry {
    /// Create a new entry with default fields.
    pub fn new(title: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            title: Zeroizing::new(title),
            username: Zeroizing::default(),
            password: SecretString::new(String::new()),
            url: Zeroizing::default(),
            notes: Zeroizing::default(),
            custom_fields: BTreeMap::new(),
            protected_fields: BTreeSet::from(["Password".to_string()]),
            attachments: Vec::new(),
            tags: Vec::new(),
            times: Times::now(),
            previous_parent_group: None,
            extra: Vec::new(),
            history: Vec::new(),
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
        self.title = Zeroizing::new(title);
    }

    /// Entry username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Update entry username.
    pub fn set_username(&mut self, username: String) {
        self.username = Zeroizing::new(username);
    }

    /// Entry password.
    pub fn password(&self) -> &SecretString {
        &self.password
    }

    /// Update entry password.
    pub fn set_password(&mut self, password: SecretString) {
        self.password = password;
    }

    /// Entry URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Update entry URL.
    pub fn set_url(&mut self, url: String) {
        self.url = Zeroizing::new(url);
    }

    /// Entry notes.
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// Update entry notes.
    pub fn set_notes(&mut self, notes: String) {
        self.notes = Zeroizing::new(notes);
    }

    /// Set a custom field value.
    pub fn set_custom_field(&mut self, key: String, value: String, protected: bool) {
        self.set_protected(&key, protected);
        self.custom_fields.insert(key, Zeroizing::new(value));
    }

    /// Return custom fields.
    pub fn custom_fields(&self) -> &BTreeMap<String, Zeroizing<String>> {
        &self.custom_fields
    }

    /// Names of the fields (standard or custom) marked for in-memory
    /// protection. They are written encrypted with the inner stream.
    pub fn protected_fields(&self) -> &BTreeSet<String> {
        &self.protected_fields
    }

    /// Mark a field (standard or custom) as protected or not.
    pub fn set_protected(&mut self, key: &str, protected: bool) {
        if protected {
            self.protected_fields.insert(key.to_string());
        } else {
            self.protected_fields.remove(key);
        }
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

    /// Entry tags, trimmed, without duplicates and sorted.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Set the tags from text such as `"work, mail; bank"`.
    ///
    /// Like KeePassXC: split on `,`, `;` or tab, trimmed, without
    /// duplicates, sorted.
    pub fn set_tags(&mut self, text: &str) {
        let tags: BTreeSet<&str> = text
            .split([',', ';', '\t'])
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .collect();
        self.tags = tags.into_iter().map(str::to_string).collect();
    }

    /// Creation, modification, access, expiry and move times.
    pub fn times(&self) -> &Times {
        &self.times
    }

    /// Mutable access to the times.
    pub fn times_mut(&mut self) -> &mut Times {
        &mut self.times
    }

    /// The group the entry was in before its last move, if known.
    pub fn previous_parent_group(&self) -> Option<Uuid> {
        self.previous_parent_group
    }

    /// Record the group the entry was in before a move.
    pub fn set_previous_parent_group(&mut self, group: Option<Uuid>) {
        self.previous_parent_group = group;
    }

    /// Record the current state in the history and mark the entry as modified now.
    ///
    /// Call this before changing an existing entry, like KeePassXC does, so the
    /// previous password and fields stay recoverable. The history is then cut
    /// to `limits`, dropping the oldest items first.
    pub fn begin_update(&mut self, limits: HistoryLimits) {
        let mut snapshot = self.clone();
        snapshot.history.clear();
        self.history.push(snapshot);
        self.truncate_history(limits);
        let now = Timestamp::now();
        self.times.last_modification = now;
        self.times.last_access = now;
    }

    /// Drop the oldest history items beyond `limits`, as KeePassXC does.
    pub fn truncate_history(&mut self, limits: HistoryLimits) {
        if let Ok(max_items) = usize::try_from(limits.max_items)
            && self.history.len() > max_items
        {
            let excess = self.history.len() - max_items;
            self.history.drain(..excess);
        }
        if limits.max_size >= 0 {
            // Keep the newest items whose sizes add up to at most max_size.
            let mut total: i64 = 0;
            let mut keep = 0;
            for item in self.history.iter().rev() {
                total = total.saturating_add(item.size());
                if total > limits.max_size {
                    break;
                }
                keep += 1;
            }
            let excess = self.history.len() - keep;
            self.history.drain(..excess);
        }
    }

    /// Approximate size in bytes, used for the history size limit: the
    /// field names and values, attachment names and data, and tags. Like
    /// KeePassXC's count, without Auto-Type and custom data.
    pub fn size(&self) -> i64 {
        let standard = [
            ("Title", self.title.as_str()),
            ("UserName", self.username.as_str()),
            ("Password", self.password.expose_secret().as_str()),
            ("URL", self.url.as_str()),
            ("Notes", self.notes.as_str()),
        ];
        let fields: usize = standard
            .into_iter()
            .map(|(key, value)| key.len() + value.len())
            .chain(
                self.custom_fields
                    .iter()
                    .map(|(key, value)| key.len() + value.len()),
            )
            .sum();
        let attachments: usize = self
            .attachments
            .iter()
            .map(|attachment| attachment.name.len() + attachment.data.len())
            .sum();
        let tags: usize = self.tags.iter().map(String::len).sum();
        i64::try_from(fields + attachments + tags).unwrap_or(i64::MAX)
    }
}

/// A group of entries in the database.
#[derive(Debug, Clone)]
pub struct Group {
    uuid: Uuid,
    name: String,
    tags: String,
    times: Times,
    previous_parent_group: Option<Uuid>,
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
            tags: String::new(),
            times: Times::now(),
            previous_parent_group: None,
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

    /// Group tags (KDBX 4.1), as stored.
    pub fn tags(&self) -> &str {
        &self.tags
    }

    /// Set the group tags.
    pub fn set_tags(&mut self, tags: String) {
        self.tags = tags;
    }

    /// Creation, modification, access, expiry and move times.
    pub fn times(&self) -> &Times {
        &self.times
    }

    /// Mutable access to the times.
    pub fn times_mut(&mut self) -> &mut Times {
        &mut self.times
    }

    /// The group this group was in before its last move, if known.
    pub fn previous_parent_group(&self) -> Option<Uuid> {
        self.previous_parent_group
    }

    /// Record the parent group before a move.
    pub fn set_previous_parent_group(&mut self, group: Option<Uuid>) {
        self.previous_parent_group = group;
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

    /// Find an entry in this group or a descendant by UUID.
    pub fn entry_by_uuid(&self, uuid: Uuid) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.uuid == uuid)
            .or_else(|| {
                self.groups
                    .iter()
                    .find_map(|child| child.entry_by_uuid(uuid))
            })
    }

    /// UUID of the group directly holding the entry `uuid`, searching this
    /// group and its descendants.
    pub fn parent_of_entry(&self, uuid: Uuid) -> Option<Uuid> {
        if self.entries.iter().any(|entry| entry.uuid == uuid) {
            return Some(self.uuid);
        }
        self.groups
            .iter()
            .find_map(|child| child.parent_of_entry(uuid))
    }

    /// UUID of the group directly holding the group `uuid`, searching this
    /// group and its descendants.
    pub fn parent_of_group(&self, uuid: Uuid) -> Option<Uuid> {
        if self.groups.iter().any(|group| group.uuid == uuid) {
            return Some(self.uuid);
        }
        self.groups
            .iter()
            .find_map(|child| child.parent_of_group(uuid))
    }

    /// Remove the entry `uuid` from this group or a descendant.
    pub fn take_entry_by_uuid(&mut self, uuid: Uuid) -> Option<Entry> {
        if let Some(index) = self.entries.iter().position(|entry| entry.uuid == uuid) {
            return Some(self.entries.remove(index));
        }
        self.groups
            .iter_mut()
            .find_map(|child| child.take_entry_by_uuid(uuid))
    }

    /// Remove the group `uuid` (a descendant, not this group) with its contents.
    pub fn take_group_by_uuid(&mut self, uuid: Uuid) -> Option<Group> {
        if let Some(index) = self.groups.iter().position(|group| group.uuid == uuid) {
            return Some(self.groups.remove(index));
        }
        self.groups
            .iter_mut()
            .find_map(|child| child.take_group_by_uuid(uuid))
    }

    /// UUIDs of every entry and group inside this group, not counting itself.
    pub fn descendant_uuids(&self) -> Vec<Uuid> {
        let mut uuids = Vec::new();
        self.collect_descendants(&mut uuids);
        uuids
    }

    fn collect_descendants(&self, uuids: &mut Vec<Uuid>) {
        uuids.extend(self.entries.iter().map(|entry| entry.uuid));
        for child in &self.groups {
            child.collect_descendants(uuids);
            uuids.push(child.uuid);
        }
    }

    /// Copy of this group's own data (UUID, name, tags, times, preserved
    /// XML) without children.
    pub fn shell(&self) -> Group {
        Group {
            uuid: self.uuid,
            name: self.name.clone(),
            tags: self.tags.clone(),
            times: self.times,
            previous_parent_group: self.previous_parent_group,
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
    recycle_bin_enabled: bool,
    recycle_bin: Option<Uuid>,
    recycle_bin_changed: Timestamp,
    history_limits: HistoryLimits,
    custom_icons: Vec<RawElement>,
    extra: Vec<RawElement>,
}

impl Meta {
    /// Create metadata with a name and KeePassXC's default settings.
    pub fn new(name: String) -> Self {
        Self {
            name,
            description: String::new(),
            recycle_bin_enabled: true,
            recycle_bin: None,
            recycle_bin_changed: Timestamp::now(),
            history_limits: HistoryLimits::default(),
            custom_icons: Vec::new(),
            extra: Vec::new(),
        }
    }

    /// Whether deleted items go to the recycle bin first.
    pub fn recycle_bin_enabled(&self) -> bool {
        self.recycle_bin_enabled
    }

    /// Turn the recycle bin on or off.
    pub fn set_recycle_bin_enabled(&mut self, enabled: bool) {
        self.recycle_bin_enabled = enabled;
    }

    /// UUID of the recycle bin group, once one exists.
    pub fn recycle_bin(&self) -> Option<Uuid> {
        self.recycle_bin
    }

    /// When the recycle bin group was last set.
    pub fn recycle_bin_changed(&self) -> Timestamp {
        self.recycle_bin_changed
    }

    /// Point the recycle bin at a group (or none), recording the time.
    pub fn set_recycle_bin(&mut self, group: Option<Uuid>) {
        self.recycle_bin = group;
        self.recycle_bin_changed = Timestamp::now();
    }

    /// Set the recycle bin fields as read from a file.
    pub fn load_recycle_bin(&mut self, group: Option<Uuid>, changed: Timestamp) {
        self.recycle_bin = group;
        self.recycle_bin_changed = changed;
    }

    /// How much history each entry keeps.
    pub fn history_limits(&self) -> HistoryLimits {
        self.history_limits
    }

    /// Change how much history each entry keeps.
    pub fn set_history_limits(&mut self, limits: HistoryLimits) {
        self.history_limits = limits;
    }

    /// Custom icons, one preserved `<Icon>` element each.
    pub fn custom_icons(&self) -> &[RawElement] {
        &self.custom_icons
    }

    /// Mutable access to the custom icons.
    pub fn custom_icons_mut(&mut self) -> &mut Vec<RawElement> {
        &mut self.custom_icons
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
    deleted_objects: Vec<DeletedObject>,
    root_extra: Vec<RawElement>,
}

/// A record that an entry or group was deleted, so a merge does not bring
/// it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletedObject {
    /// UUID of the deleted entry or group.
    pub uuid: Uuid,
    /// When it was deleted.
    pub deletion_time: Timestamp,
}

/// What [`Database::recycle_entry`] and [`Database::recycle_group`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// Moved into the recycle bin.
    Recycled,
    /// Deleted for good: the recycle bin is off, or the item was already in it.
    Deleted,
}

impl Database {
    /// Create a new database with a root group.
    pub fn new(name: String) -> Self {
        Self {
            meta: Meta::new(name.clone()),
            root: Group::new(name),
            deleted_objects: Vec::new(),
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

    /// Records of deleted entries and groups.
    pub fn deleted_objects(&self) -> &[DeletedObject] {
        &self.deleted_objects
    }

    /// Mutable access to the deletion records.
    pub fn deleted_objects_mut(&mut self) -> &mut Vec<DeletedObject> {
        &mut self.deleted_objects
    }

    /// Delete the entry `uuid` for good and record the deletion.
    pub fn delete_entry(&mut self, uuid: Uuid) -> Option<Entry> {
        let entry = self.root.take_entry_by_uuid(uuid)?;
        self.record_deletion(uuid);
        Some(entry)
    }

    /// Delete the group `uuid` and everything in it for good, recording
    /// each deletion. The root group cannot be deleted.
    pub fn delete_group(&mut self, uuid: Uuid) -> Option<Group> {
        let group = self.root.take_group_by_uuid(uuid)?;
        let mut removed = group.descendant_uuids();
        removed.push(uuid);
        for item in &removed {
            self.record_deletion(*item);
        }
        if let Some(bin) = self.meta.recycle_bin
            && removed.contains(&bin)
        {
            self.meta.set_recycle_bin(None);
        }
        Some(group)
    }

    fn record_deletion(&mut self, uuid: Uuid) {
        self.deleted_objects.push(DeletedObject {
            uuid,
            deletion_time: Timestamp::now(),
        });
    }

    /// Move the entry `uuid` into the group `target`, recording where it
    /// came from. Returns false if either is missing; moving an entry to
    /// the group it is already in changes nothing.
    pub fn move_entry(&mut self, uuid: Uuid, target: Uuid) -> bool {
        let Some(parent) = self.root.parent_of_entry(uuid) else {
            return false;
        };
        if self.root.group_by_uuid(target).is_none() {
            return false;
        }
        if parent == target {
            return true;
        }
        let Some(mut entry) = self.root.take_entry_by_uuid(uuid) else {
            return false;
        };
        entry.previous_parent_group = Some(parent);
        entry.times.location_changed = Timestamp::now();
        if let Some(group) = self.root.group_by_uuid_mut(target) {
            group.entries.push(entry);
        }
        true
    }

    /// Move the group `uuid` into the group `target`, recording where it
    /// came from. Returns false if either is missing, `uuid` is the root,
    /// or `target` is inside the group being moved.
    pub fn move_group(&mut self, uuid: Uuid, target: Uuid) -> bool {
        let Some(parent) = self.root.parent_of_group(uuid) else {
            return false;
        };
        let target_inside = self
            .root
            .group_by_uuid(uuid)
            .is_some_and(|group| group.group_by_uuid(target).is_some());
        if target_inside || self.root.group_by_uuid(target).is_none() {
            return false;
        }
        if parent == target {
            return true;
        }
        let Some(mut group) = self.root.take_group_by_uuid(uuid) else {
            return false;
        };
        group.previous_parent_group = Some(parent);
        group.times.location_changed = Timestamp::now();
        if let Some(destination) = self.root.group_by_uuid_mut(target) {
            destination.groups.push(group);
        }
        true
    }

    /// True if `uuid` is the recycle bin or inside it.
    pub fn in_recycle_bin(&self, uuid: Uuid) -> bool {
        let Some(bin) = self
            .meta
            .recycle_bin
            .and_then(|bin| self.root.group_by_uuid(bin))
        else {
            return false;
        };
        bin.uuid == uuid || bin.group_by_uuid(uuid).is_some() || bin.entry_by_uuid(uuid).is_some()
    }

    /// Remove an entry like KeePassXC: into the recycle bin when it is on,
    /// for good when it is off or the entry is already in the bin.
    pub fn recycle_entry(&mut self, uuid: Uuid) -> Option<Removal> {
        if !self.meta.recycle_bin_enabled || self.in_recycle_bin(uuid) {
            return self.delete_entry(uuid).map(|_| Removal::Deleted);
        }
        self.root.entry_by_uuid(uuid)?;
        let bin = self.recycle_bin_group();
        self.move_entry(uuid, bin).then_some(Removal::Recycled)
    }

    /// Remove a group like KeePassXC: into the recycle bin when it is on,
    /// for good when it is off or the group is already in the bin.
    pub fn recycle_group(&mut self, uuid: Uuid) -> Option<Removal> {
        if !self.meta.recycle_bin_enabled || self.in_recycle_bin(uuid) {
            return self.delete_group(uuid).map(|_| Removal::Deleted);
        }
        self.root.parent_of_group(uuid)?;
        let bin = self.recycle_bin_group();
        self.move_group(uuid, bin).then_some(Removal::Recycled)
    }

    /// The recycle bin group, created in the root group if there is none.
    fn recycle_bin_group(&mut self) -> Uuid {
        if let Some(bin) = self.meta.recycle_bin
            && self.root.group_by_uuid(bin).is_some()
        {
            return bin;
        }
        let mut bin = Group::new("Recycle Bin".to_string());
        bin.extra = vec![
            RawElement::new(
                "IconID".to_string(),
                format!("<IconID>{RECYCLE_BIN_ICON}</IconID>"),
            ),
            RawElement::new(
                "EnableAutoType".to_string(),
                "<EnableAutoType>false</EnableAutoType>".to_string(),
            ),
            RawElement::new(
                "EnableSearching".to_string(),
                "<EnableSearching>false</EnableSearching>".to_string(),
            ),
        ];
        let uuid = bin.uuid;
        self.root.groups.push(bin);
        self.meta.set_recycle_bin(Some(uuid));
        uuid
    }

    /// Uninterpreted `Root` children preserved from the source file.
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
        assert_eq!(
            entry.custom_fields().get("key").map(|value| value.as_str()),
            Some("value")
        );
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
    fn begin_update_keeps_previous_version() {
        let mut entry = Entry::new("Title".to_string());
        entry.set_password(SecretString::new("old".to_string()));
        entry.times_mut().last_modification = Timestamp::from_secs(0);
        entry.begin_update(HistoryLimits::default());
        entry.set_password(SecretString::new("new".to_string()));

        assert_eq!(entry.history().len(), 1);
        assert_eq!(entry.history()[0].password().expose_secret(), "old");
        assert_eq!(entry.history()[0].times().last_modification.secs(), 0);
        assert!(entry.times().last_modification > Timestamp::from_secs(0));
    }

    #[test]
    fn history_follows_the_item_limit() {
        let mut entry = Entry::new("Title".to_string());
        for _ in 0..(DEFAULT_HISTORY_MAX_ITEMS + 5) {
            entry.begin_update(HistoryLimits::default());
        }
        assert_eq!(entry.history().len(), 10);

        let three = HistoryLimits {
            max_items: 3,
            max_size: -1,
        };
        entry.begin_update(three);
        assert_eq!(entry.history().len(), 3);

        let unlimited = HistoryLimits {
            max_items: -1,
            max_size: -1,
        };
        for _ in 0..20 {
            entry.begin_update(unlimited);
        }
        assert_eq!(entry.history().len(), 23);
    }

    #[test]
    fn history_follows_the_size_limit() {
        let mut entry = Entry::new("T".to_string());
        let limits = HistoryLimits {
            max_items: -1,
            max_size: 2500,
        };
        for round in 0..5 {
            entry.set_notes(format!("{round}").repeat(1000));
            entry.begin_update(limits);
        }
        // Each item is a little over 1000 bytes, so two fit.
        assert_eq!(entry.history().len(), 2);
        assert!(entry.history()[1].notes().starts_with('4'));

        entry.begin_update(HistoryLimits {
            max_items: -1,
            max_size: 0,
        });
        assert!(entry.history().is_empty());
    }

    #[test]
    fn tags_are_normalised_like_keepassxc() {
        let mut entry = Entry::new("T".to_string());
        entry.set_tags(" work;mail,\twork , ;bank");
        assert_eq!(entry.tags(), ["bank", "mail", "work"]);
    }

    fn sample() -> (Database, Uuid, Uuid, Uuid) {
        let mut db = Database::new("Root".to_string());
        let entry = Entry::new("Mail".to_string());
        let entry_uuid = entry.uuid();
        let mut work = Group::new("Work".to_string());
        let work_uuid = work.uuid();
        work.entries_mut().push(entry);
        let mut inner = Group::new("Inner".to_string());
        let inner_uuid = inner.uuid();
        inner.entries_mut().push(Entry::new("Deep".to_string()));
        work.groups_mut().push(inner);
        db.root_mut().groups_mut().push(work);
        (db, entry_uuid, work_uuid, inner_uuid)
    }

    #[test]
    fn removing_an_entry_recycles_it_then_deletes_it() {
        let (mut db, entry, work, _) = sample();
        assert_eq!(db.recycle_entry(entry), Some(Removal::Recycled));
        let bin = db.meta().recycle_bin().expect("bin created");
        let bin_group = db.root().group_by_uuid(bin).expect("bin group");
        assert_eq!(bin_group.name(), "Recycle Bin");
        let recycled = bin_group.entry_by_uuid(entry).expect("in bin");
        assert_eq!(recycled.previous_parent_group(), Some(work));
        assert!(db.deleted_objects().is_empty());

        assert_eq!(db.recycle_entry(entry), Some(Removal::Deleted));
        assert!(db.root().entry_by_uuid(entry).is_none());
        assert_eq!(db.deleted_objects()[0].uuid, entry);
        assert_eq!(db.recycle_entry(entry), None);
    }

    #[test]
    fn removing_with_the_recycle_bin_off_deletes() {
        let (mut db, entry, work, inner) = sample();
        db.meta_mut().set_recycle_bin_enabled(false);
        assert_eq!(db.recycle_entry(entry), Some(Removal::Deleted));
        assert_eq!(db.recycle_group(work), Some(Removal::Deleted));
        assert!(db.meta().recycle_bin().is_none());
        let deleted: Vec<Uuid> = db.deleted_objects().iter().map(|item| item.uuid).collect();
        assert!(deleted.contains(&entry));
        assert!(deleted.contains(&work));
        assert!(deleted.contains(&inner));
        // The entry inside Inner too.
        assert_eq!(deleted.len(), 4);
    }

    #[test]
    fn deleting_the_recycle_bin_forgets_it() {
        let (mut db, _, work, _) = sample();
        assert_eq!(db.recycle_group(work), Some(Removal::Recycled));
        let bin = db.meta().recycle_bin().expect("bin");
        assert_eq!(db.recycle_group(bin), Some(Removal::Deleted));
        assert!(db.meta().recycle_bin().is_none());
        assert!(db.root().groups().is_empty());
    }

    #[test]
    fn moves_record_the_previous_group() {
        let (mut db, entry, work, inner) = sample();
        let root = db.root().uuid();
        let before = db
            .root()
            .entry_by_uuid(entry)
            .expect("entry")
            .times()
            .location_changed;
        db.root_mut()
            .entry_by_uuid_mut(entry)
            .expect("entry")
            .times_mut()
            .location_changed = Timestamp::from_secs(0);
        assert!(db.move_entry(entry, inner));
        let moved = db.root().entry_by_uuid(entry).expect("entry");
        assert_eq!(moved.previous_parent_group(), Some(work));
        assert!(moved.times().location_changed >= before);
        assert!(moved.history().is_empty());

        assert!(db.move_group(inner, root));
        assert_eq!(
            db.root()
                .group_by_uuid(inner)
                .expect("inner")
                .previous_parent_group(),
            Some(work)
        );
        // A group cannot move into itself.
        assert!(!db.move_group(work, work));
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
