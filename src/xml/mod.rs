//! KeePass XML parser and writer.
//!
//! Elements keepassxcr interprets (names, strings, attachments, history) are
//! parsed into the model. Every other element is kept verbatim as a
//! [`RawElement`] and written back unchanged, so that saving a database created
//! by KeePassXC does not drop timestamps, tags, icons, auto-type settings,
//! custom data, deleted objects or metadata settings.

// This code parses untrusted files: a malformed one must give an error, never
// a panic, so indexing and unwrap are not allowed here (tests excepted).
#![cfg_attr(
    not(test),
    deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)
)]

use std::collections::HashMap;
use std::io::{Cursor, Read};

use base64::Engine as _;
use quick_xml::Reader;
use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesRef, BytesStart, BytesText, Event};
use quick_xml::name::QName;
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::crypto::{ProtectedStream, ProtectedStreamAlgo};
use crate::error::{AppError, AppResult};
use crate::model::{
    Attachment, Database, DeletedObject, Entry, Group, HistoryLimits, RawElement, Times, Timestamp,
};
use zeroize::Zeroizing;

/// Where the attachment pool is stored when writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
///
/// It also picks the rest of the format: KDBX4 (`InnerHeader`) writes times
/// as base64 seconds and the 4.1 elements, KDBX3 (`Meta`) writes ISO 8601
/// times and leaves out elements that KDBX 3.1 does not have.
pub enum BinaryPool {
    /// KDBX4: the pool is returned to the caller for the inner header.
    InnerHeader,
    /// KDBX3: the pool is written to `Meta/Binaries`.
    Meta,
}

/// One attachment in a database's shared pool.
#[derive(Clone)]
pub struct PoolBinary {
    /// Attachment bytes, wiped when dropped.
    pub data: Zeroizing<Vec<u8>>,
    /// The memory-protection flag (bit 0 of the KDBX 4 inner-header flag byte).
    pub protected: bool,
}

impl PoolBinary {
    /// Wrap attachment bytes with their protection flag.
    pub fn new(data: Vec<u8>, protected: bool) -> Self {
        Self {
            data: Zeroizing::new(data),
            protected,
        }
    }
}

impl std::fmt::Debug for PoolBinary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolBinary")
            .field("len", &self.data.len())
            .field("protected", &self.protected)
            .finish()
    }
}

/// XML output with attachment pool.
#[derive(Debug, Clone)]
pub struct XmlOutput {
    /// Serialized XML bytes.
    pub xml: Vec<u8>,
    /// Attachment pool in the order referenced by the XML.
    pub attachments: Vec<PoolBinary>,
}

/// Parse a KeePass XML document into a database.
///
/// `attachments` is the KDBX4 inner-header attachment pool; for KDBX3 pass an
/// empty slice and the pool is read from `Meta/Binaries`.
///
/// `header_hash` is the SHA-256 of a KDBX 3.1 file's outer header. When the
/// document stores a `Meta/HeaderHash` it must match, as in KeePassXC: the
/// KDBX3 header is otherwise unauthenticated.
pub fn read_database(
    xml: &[u8],
    attachments: &[PoolBinary],
    protected_stream_key: &[u8],
    algo: ProtectedStreamAlgo,
    header_hash: Option<&[u8]>,
) -> AppResult<Database> {
    let xml = std::str::from_utf8(xml).map_err(|_| AppError::Xml("invalid utf8".to_string()))?;
    let mut reader = Reader::from_str(xml);
    // Values keep their leading and trailing whitespace, as in KeePassXC.
    reader.config_mut().trim_text(false);
    let mut parser = Parser {
        reader,
        input: xml,
        stream: ProtectedStream::new(algo, protected_stream_key)?,
        binaries: attachments.to_vec(),
        meta_binaries: HashMap::new(),
        depth: 0,
        header_hash: None,
    };
    let database = parser.parse_document()?;
    if let (Some(expected), Some(stored)) = (header_hash, parser.header_hash.as_deref()) {
        let stored = base64::engine::general_purpose::STANDARD
            .decode(stored.trim())
            .map_err(|_| AppError::Format("invalid header hash".to_string()))?;
        if stored != expected {
            return Err(AppError::Format("header hash mismatch".to_string()));
        }
    }
    Ok(database)
}

/// True if saving `database` needs KDBX 4.1 rather than 4.0, following
/// KeePassXC: group tags, a previous parent group, an entry excluded from
/// reports, or a custom icon with a name or modification time.
pub fn requires_kdbx41(database: &Database) -> bool {
    let meta_needs =
        database.meta().custom_icons().iter().any(|icon| {
            icon.xml().contains("<Name>") || icon.xml().contains("<LastModificationTime>")
        });
    meta_needs || group_requires_kdbx41(database.root())
}

fn group_requires_kdbx41(group: &Group) -> bool {
    let group_needs = !group.tags().trim().is_empty() || group.previous_parent_group().is_some();
    let entry_needs = group.entries().iter().any(|entry| {
        entry.previous_parent_group().is_some()
            || entry.extra().iter().any(|raw| {
                raw.name() == "QualityCheck"
                    && crate::model::element_text(raw.xml(), "QualityCheck")
                        .is_some_and(|value| value.trim().eq_ignore_ascii_case("false"))
            })
    });
    group_needs || entry_needs || group.groups().iter().any(group_requires_kdbx41)
}

/// Serialize a database to KeePass XML.
///
/// Protected values are encrypted with the inner stream in document order when
/// `protect_fields` is true (always the case inside a KDBX file).
///
/// `header_hash`, for KDBX 3.1, is the SHA-256 of the outer header and is
/// stored as `Meta/HeaderHash`.
pub fn write_database(
    database: &Database,
    protected_stream_key: &[u8],
    algo: ProtectedStreamAlgo,
    protect_fields: bool,
    pool: BinaryPool,
    header_hash: Option<&[u8]>,
) -> AppResult<XmlOutput> {
    let mut output = Vec::new();
    let mut writer = Writer::new_with_indent(Cursor::new(&mut output), b'\t', 1);
    let mut stream = ProtectedStream::new(algo, protected_stream_key)?;
    let (attachments, index) = build_attachment_pool(database.root());

    writer
        .write_event(Event::Decl(quick_xml::events::BytesDecl::new(
            "1.0",
            Some("UTF-8"),
            Some("yes"),
        )))
        .map_err(xml_write_error)?;
    start(&mut writer, BytesStart::new("KeePassFile"))?;

    let meta_pool = if pool == BinaryPool::Meta {
        attachments.as_slice()
    } else {
        &[]
    };
    write_meta(
        &mut writer,
        database,
        meta_pool,
        header_hash,
        pool == BinaryPool::InnerHeader,
    )?;

    let mut ctx = WriteContext {
        stream: &mut stream,
        index: &index,
        protect_fields,
        memory_protection: MemoryProtection::of(database),
        kdbx4: pool == BinaryPool::InnerHeader,
    };
    start(&mut writer, BytesStart::new("Root"))?;
    write_group(&mut writer, database.root(), &mut ctx)?;
    write_deleted_objects(&mut writer, database.deleted_objects(), ctx.kdbx4)?;
    write_raw(&mut writer, database.root_extra())?;
    end(&mut writer, "Root")?;

    end(&mut writer, "KeePassFile")?;

    let attachments = if pool == BinaryPool::InnerHeader {
        attachments
    } else {
        Vec::new()
    };
    Ok(XmlOutput {
        xml: output,
        attachments,
    })
}

// ─── Reading ────────────────────────────────────────────────────────────────

/// Streaming parser state.
///
/// The inner random stream must be applied to protected values in document
/// order, so a single parser walks the whole document once.
struct Parser<'a> {
    reader: Reader<&'a [u8]>,
    input: &'a str,
    stream: ProtectedStream,
    /// KDBX4 inner-header attachment pool, indexed by position.
    binaries: Vec<PoolBinary>,
    /// KDBX3 `Meta/Binaries` pool, keyed by the `ID` attribute.
    ///
    /// A map rather than a vector so that a huge `ID` from the file cannot
    /// cause a huge allocation.
    meta_binaries: HashMap<usize, PoolBinary>,
    /// Current `Group`/`Entry` nesting depth.
    depth: usize,
    /// Base64 `Meta/HeaderHash`, if the document has one.
    header_hash: Option<String>,
}

/// Deepest `Group`/`History` nesting accepted when parsing.
///
/// Parsing recurses per level, so an unbounded depth from a hostile file would
/// overflow the stack. Real databases are nowhere near this.
const MAX_DEPTH: usize = 256;

/// Largest decompressed size accepted for the payload or one attachment.
///
/// KeePassXC 2.7 keeps these in a `QByteArray`, which cannot exceed 2 GiB, so
/// nothing KeePassXC writes is larger. The limit stops a small compressed file
/// from expanding into many gigabytes of memory.
pub const MAX_DECOMPRESSED_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Gunzip `data`, failing instead of growing past [`MAX_DECOMPRESSED_SIZE`].
pub fn gunzip_limited(data: &[u8]) -> AppResult<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(MAX_DECOMPRESSED_SIZE + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > MAX_DECOMPRESSED_SIZE {
        return Err(AppError::Format(
            "decompressed data is larger than 2 GiB".to_string(),
        ));
    }
    Ok(out)
}

/// One child event of an element being parsed.
enum Child {
    /// A start tag with its name and attributes (owned so the reader can advance).
    Start(String, Vec<(String, String)>, usize),
    /// A self-closing tag.
    Empty(String, Vec<(String, String)>, usize),
    /// The end tag of the parent element.
    End,
}

impl<'a> Parser<'a> {
    fn parse_document(&mut self) -> AppResult<Database> {
        let mut database = Database::new("Database".to_string());
        let mut root_group = None;
        loop {
            match self.reader.read_event() {
                Ok(Event::Start(e)) if e.name().0 == "Meta" => {
                    self.parse_meta(&mut database)?;
                }
                Ok(Event::Start(e)) if e.name().0 == "Root" => {
                    root_group = Some(self.parse_root(&mut database)?);
                }
                Ok(Event::Eof) => break,
                Err(err) => return Err(AppError::Xml(format!("xml parse error: {err}"))),
                _ => {}
            }
        }
        if let Some(group) = root_group {
            *database.root_mut() = group;
        }
        Ok(database)
    }

    /// Read the next child event of the current element.
    fn next_child(&mut self) -> AppResult<Child> {
        loop {
            let start_pos = self.reader.buffer_position() as usize;
            match self.reader.read_event() {
                Ok(Event::Start(e)) => {
                    return Ok(Child::Start(e.name().0.to_string(), attrs(&e), start_pos));
                }
                Ok(Event::Empty(e)) => {
                    return Ok(Child::Empty(e.name().0.to_string(), attrs(&e), start_pos));
                }
                Ok(Event::End(_)) | Ok(Event::Eof) => return Ok(Child::End),
                Err(err) => return Err(AppError::Xml(format!("xml parse error: {err}"))),
                _ => {}
            }
        }
    }

    /// Skip the rest of an element whose start tag was just read and return it verbatim.
    fn capture(&mut self, name: &str, start_pos: usize) -> AppResult<RawElement> {
        self.reader
            .read_to_end(QName(name))
            .map_err(|err| AppError::Xml(format!("xml parse error: {err}")))?;
        self.raw_since(name, start_pos)
    }

    /// Return the source text from `start_pos` to the reader position as a raw element.
    fn raw_since(&self, name: &str, start_pos: usize) -> AppResult<RawElement> {
        let end_pos = self.reader.buffer_position() as usize;
        let xml = self
            .input
            .get(start_pos..end_pos)
            .ok_or_else(|| AppError::Xml("invalid element bounds".to_string()))?
            .trim()
            .to_string();
        Ok(RawElement::new(name.to_string(), xml))
    }

    /// Read the text content of a leaf element whose start tag was just read.
    fn read_text(&mut self) -> AppResult<String> {
        let mut text = String::new();
        loop {
            match self.reader.read_event() {
                Ok(Event::Text(e)) => text.push_str(&e.xml10_content()),
                Ok(Event::GeneralRef(e)) => text.push(resolve_reference(&e)?),
                Ok(Event::CData(e)) => text.push_str(&e.into_inner()),
                Ok(Event::End(_)) | Ok(Event::Eof) => break,
                Ok(Event::Start(e)) => {
                    let name = e.name().0.to_string();
                    self.reader
                        .read_to_end(QName(name.as_str()))
                        .map_err(|err| AppError::Xml(format!("xml parse error: {err}")))?;
                }
                Err(err) => return Err(AppError::Xml(format!("xml text error: {err}"))),
                _ => {}
            }
        }
        Ok(text)
    }

    fn parse_meta(&mut self, database: &mut Database) -> AppResult<()> {
        let mut recycle_bin = None;
        let mut recycle_bin_changed = None;
        let mut limits = HistoryLimits::default();
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, pos) => match name.as_str() {
                    "RecycleBinEnabled" => {
                        let value = self.read_text()?;
                        database
                            .meta_mut()
                            .set_recycle_bin_enabled(parse_bool(&value, true));
                    }
                    "RecycleBinUUID" => {
                        recycle_bin = parse_uuid(&self.read_text()?)?;
                    }
                    "RecycleBinChanged" => {
                        recycle_bin_changed = Timestamp::parse(&self.read_text()?);
                    }
                    "HistoryMaxItems" => {
                        if let Ok(value) = self.read_text()?.trim().parse() {
                            limits.max_items = value;
                        }
                    }
                    "HistoryMaxSize" => {
                        if let Ok(value) = self.read_text()?.trim().parse() {
                            limits.max_size = value;
                        }
                    }
                    "CustomIcons" => self.parse_custom_icons(database)?,
                    "DatabaseName" => {
                        let value = self.read_text()?;
                        database.meta_mut().set_name(value);
                    }
                    "DatabaseDescription" => {
                        let value = self.read_text()?;
                        database.meta_mut().set_description(value);
                    }
                    // Regenerated on write.
                    "Generator" => {
                        self.read_text()?;
                    }
                    "HeaderHash" => {
                        let value = self.read_text()?;
                        if !value.trim().is_empty() {
                            self.header_hash = Some(value);
                        }
                    }
                    "Binaries" => self.parse_meta_binaries()?,
                    _ => {
                        let raw = self.capture(&name, pos)?;
                        database.meta_mut().extra_mut().push(raw);
                    }
                },
                Child::Empty(name, _, pos) => match name.as_str() {
                    "DatabaseName" => database.meta_mut().set_name(String::new()),
                    "DatabaseDescription" => database.meta_mut().set_description(String::new()),
                    "Generator" | "HeaderHash" | "Binaries" | "CustomIcons" | "RecycleBinUUID"
                    | "RecycleBinEnabled" | "RecycleBinChanged" | "HistoryMaxItems"
                    | "HistoryMaxSize" => {}
                    _ => {
                        let raw = self.raw_since(&name, pos)?;
                        database.meta_mut().extra_mut().push(raw);
                    }
                },
            }
        }
        let changed = recycle_bin_changed.unwrap_or_else(|| database.meta().recycle_bin_changed());
        database.meta_mut().load_recycle_bin(recycle_bin, changed);
        database.meta_mut().set_history_limits(limits);
        Ok(())
    }

    /// Keep each `Meta/CustomIcons/Icon` as written.
    fn parse_custom_icons(&mut self, database: &mut Database) -> AppResult<()> {
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, pos) => {
                    let raw = self.capture(&name, pos)?;
                    if name == "Icon" {
                        database.meta_mut().custom_icons_mut().push(raw);
                    }
                }
                Child::Empty(..) => {}
            }
        }
        Ok(())
    }

    /// Parse a `Times` block. Unknown children are dropped, and a missing
    /// or unreadable time is the current time, as in KeePassXC.
    fn parse_times(&mut self) -> AppResult<Times> {
        let mut times = Times::now();
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, _) => {
                    let text = self.read_text()?;
                    let stamp = Timestamp::parse(&text);
                    match name.as_str() {
                        "CreationTime" => times.creation = stamp.unwrap_or(times.creation),
                        "LastModificationTime" => {
                            times.last_modification = stamp.unwrap_or(times.last_modification);
                        }
                        "LastAccessTime" => times.last_access = stamp.unwrap_or(times.last_access),
                        "ExpiryTime" => times.expiry = stamp.unwrap_or(times.expiry),
                        "LocationChanged" => {
                            times.location_changed = stamp.unwrap_or(times.location_changed);
                        }
                        "Expires" => times.expires = parse_bool(&text, false),
                        "UsageCount" => times.usage_count = text.trim().parse().unwrap_or(0),
                        _ => {}
                    }
                }
                Child::Empty(..) => {}
            }
        }
        Ok(times)
    }

    fn parse_deleted_objects(&mut self, database: &mut Database) -> AppResult<()> {
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, _) if name == "DeletedObject" => {
                    let mut uuid = None;
                    let mut deletion_time = None;
                    loop {
                        match self.next_child()? {
                            Child::End => break,
                            Child::Start(name, _, _) => {
                                let text = self.read_text()?;
                                match name.as_str() {
                                    "UUID" => uuid = parse_uuid(&text)?,
                                    "DeletionTime" => deletion_time = Timestamp::parse(&text),
                                    _ => {}
                                }
                            }
                            Child::Empty(..) => {}
                        }
                    }
                    // Like KeePassXC, a record needs both fields.
                    if let (Some(uuid), Some(deletion_time)) = (uuid, deletion_time) {
                        database.deleted_objects_mut().push(DeletedObject {
                            uuid,
                            deletion_time,
                        });
                    }
                }
                Child::Start(name, _, _) => {
                    self.reader
                        .read_to_end(QName(name.as_str()))
                        .map_err(|err| AppError::Xml(format!("xml parse error: {err}")))?;
                }
                Child::Empty(..) => {}
            }
        }
        Ok(())
    }

    /// Parse the KDBX3 attachment pool in `Meta/Binaries`.
    fn parse_meta_binaries(&mut self) -> AppResult<()> {
        loop {
            let (attributes, data) = match self.next_child()? {
                Child::End => break,
                Child::Start(name, attributes, _) if name == "Binary" => {
                    (attributes, self.read_text()?)
                }
                Child::Empty(name, attributes, _) if name == "Binary" => {
                    (attributes, String::new())
                }
                Child::Start(name, _, _) => {
                    self.reader
                        .read_to_end(QName(name.as_str()))
                        .map_err(|err| AppError::Xml(format!("xml parse error: {err}")))?;
                    continue;
                }
                Child::Empty(..) => continue,
            };

            let id = attr(&attributes, "ID")
                .ok_or_else(|| AppError::Xml("binary without ID".to_string()))?
                .parse::<usize>()
                .map_err(|_| AppError::Xml("invalid binary ID".to_string()))?;
            let mut bytes = decode_base64(&data, "binary")?;
            let protected = attr(&attributes, "Protected").as_deref() == Some("True");
            if protected {
                self.stream.apply(&mut bytes)?;
            }
            // KeePassXC writes an empty attachment as `<Binary ID="n" Compressed="True"/>`
            // with no gzip data at all.
            if attr(&attributes, "Compressed").as_deref() == Some("True") && !bytes.is_empty() {
                bytes = gunzip_limited(&bytes)?;
            }
            self.meta_binaries
                .insert(id, PoolBinary::new(bytes, protected));
        }
        Ok(())
    }

    fn parse_root(&mut self, database: &mut Database) -> AppResult<Group> {
        let mut root_group = None;
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, _) if name == "Group" && root_group.is_none() => {
                    root_group = Some(self.parse_group()?);
                }
                Child::Start(name, _, _) if name == "DeletedObjects" => {
                    self.parse_deleted_objects(database)?;
                }
                Child::Start(name, _, pos) => {
                    let raw = self.capture(&name, pos)?;
                    database.root_extra_mut().push(raw);
                }
                Child::Empty(name, _, _) if name == "DeletedObjects" => {}
                Child::Empty(name, _, pos) => {
                    let raw = self.raw_since(&name, pos)?;
                    database.root_extra_mut().push(raw);
                }
            }
        }
        root_group.ok_or_else(|| AppError::Xml("missing root group".to_string()))
    }

    /// Enter one nesting level, failing past [`MAX_DEPTH`].
    fn descend(&mut self) -> AppResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(AppError::Xml("groups are nested too deeply".to_string()));
        }
        Ok(())
    }

    fn parse_group(&mut self) -> AppResult<Group> {
        self.descend()?;
        let group = self.parse_group_body();
        self.depth -= 1;
        group
    }

    fn parse_group_body(&mut self) -> AppResult<Group> {
        let mut group = Group::new("Group".to_string());
        let mut uuid = None;
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, pos) => match name.as_str() {
                    "UUID" => uuid = parse_uuid(&self.read_text()?)?,
                    "Name" => {
                        let value = self.read_text()?;
                        group.set_name(value);
                    }
                    "Tags" => {
                        let value = self.read_text()?;
                        group.set_tags(value);
                    }
                    "Times" => *group.times_mut() = self.parse_times()?,
                    "PreviousParentGroup" => {
                        let value = parse_uuid(&self.read_text()?)?;
                        group.set_previous_parent_group(value);
                    }
                    "Entry" => {
                        let entry = self.parse_entry()?;
                        group.entries_mut().push(entry);
                    }
                    "Group" => {
                        let child = self.parse_group()?;
                        group.groups_mut().push(child);
                    }
                    _ => {
                        let raw = self.capture(&name, pos)?;
                        group.extra_mut().push(raw);
                    }
                },
                Child::Empty(name, _, pos) => match name.as_str() {
                    "Name" => group.set_name(String::new()),
                    "UUID" | "Entry" | "Group" | "Tags" | "PreviousParentGroup" => {}
                    _ => {
                        let raw = self.raw_since(&name, pos)?;
                        group.extra_mut().push(raw);
                    }
                },
            }
        }
        if let Some(uuid) = uuid {
            group.set_uuid(uuid);
        }
        Ok(group)
    }

    fn parse_entry(&mut self) -> AppResult<Entry> {
        self.descend()?;
        let entry = self.parse_entry_body();
        self.depth -= 1;
        entry
    }

    fn parse_entry_body(&mut self) -> AppResult<Entry> {
        let mut uuid = None;
        let mut entry = Entry::new(String::new());
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, pos) => match name.as_str() {
                    "UUID" => uuid = parse_uuid(&self.read_text()?)?,
                    "Tags" => {
                        let value = self.read_text()?;
                        entry.set_tags(&value);
                    }
                    "Times" => *entry.times_mut() = self.parse_times()?,
                    "PreviousParentGroup" => {
                        let value = parse_uuid(&self.read_text()?)?;
                        entry.set_previous_parent_group(value);
                    }
                    "String" => {
                        let (key, value, protected) = self.parse_string()?;
                        entry.set_protected(&key, protected);
                        match key.as_str() {
                            "Title" => entry.set_title(value),
                            "UserName" => entry.set_username(value),
                            "Password" => entry.set_password(secrecy::SecretString::new(value)),
                            "URL" => entry.set_url(value),
                            "Notes" => entry.set_notes(value),
                            _ => entry.set_custom_field(key, value, protected),
                        }
                    }
                    "Binary" => {
                        if let Some(attachment) = self.parse_binary()? {
                            entry.attachments_mut().push(attachment);
                        }
                    }
                    "History" => self.parse_history(&mut entry)?,
                    _ => {
                        let raw = self.capture(&name, pos)?;
                        entry.extra_mut().push(raw);
                    }
                },
                Child::Empty(name, _, pos) => match name.as_str() {
                    "UUID" | "String" | "Binary" | "History" | "Tags" | "PreviousParentGroup" => {}
                    _ => {
                        let raw = self.raw_since(&name, pos)?;
                        entry.extra_mut().push(raw);
                    }
                },
            }
        }
        if let Some(uuid) = uuid {
            entry.set_uuid(uuid);
        }
        Ok(entry)
    }

    fn parse_history(&mut self, entry: &mut Entry) -> AppResult<()> {
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, _, _) if name == "Entry" => {
                    let item = self.parse_entry()?;
                    entry.history_mut().push(item);
                }
                Child::Start(name, _, _) => {
                    self.reader
                        .read_to_end(QName(name.as_str()))
                        .map_err(|err| AppError::Xml(format!("xml parse error: {err}")))?;
                }
                Child::Empty(..) => {}
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> AppResult<(String, String, bool)> {
        let mut key = String::new();
        let mut value = String::new();
        let mut protected = false;
        loop {
            match self.next_child()? {
                Child::End => break,
                Child::Start(name, attributes, _) => match name.as_str() {
                    "Key" => key = self.read_text()?,
                    "Value" => {
                        let is_protected =
                            attr(&attributes, "Protected").as_deref() == Some("True");
                        let in_memory =
                            attr(&attributes, "ProtectInMemory").as_deref() == Some("True");
                        protected = is_protected || in_memory;
                        let raw = self.read_text()?;
                        value = if is_protected {
                            let mut bytes = decode_base64(&raw, "protected value")?;
                            self.stream.apply(&mut bytes)?;
                            String::from_utf8(bytes)
                                .map_err(|_| AppError::Xml("invalid protected utf8".to_string()))?
                        } else {
                            raw
                        };
                    }
                    _ => {
                        self.reader
                            .read_to_end(QName(name.as_str()))
                            .map_err(|err| AppError::Xml(format!("xml parse error: {err}")))?;
                    }
                },
                Child::Empty(name, attributes, _) => {
                    if name == "Value" {
                        protected = attr(&attributes, "Protected").as_deref() == Some("True")
                            || attr(&attributes, "ProtectInMemory").as_deref() == Some("True");
                        value.clear();
                    }
                }
            }
        }
        Ok((key, value, protected))
    }

    fn parse_binary(&mut self) -> AppResult<Option<Attachment>> {
        let mut key = None;
        let mut value = None;
        let mut ref_index = None;
        loop {
            let attributes = match self.next_child()? {
                Child::End => break,
                Child::Start(name, attributes, _) => match name.as_str() {
                    "Key" => {
                        key = Some(self.read_text()?);
                        continue;
                    }
                    "Value" => {
                        let raw = self.read_text()?;
                        if !raw.is_empty() {
                            let mut bytes = decode_base64(&raw, "attachment")?;
                            let protected =
                                attr(&attributes, "Protected").as_deref() == Some("True");
                            if protected {
                                self.stream.apply(&mut bytes)?;
                            }
                            value = Some(PoolBinary::new(bytes, protected));
                        }
                        attributes
                    }
                    _ => {
                        self.reader
                            .read_to_end(QName(name.as_str()))
                            .map_err(|err| AppError::Xml(format!("xml parse error: {err}")))?;
                        continue;
                    }
                },
                Child::Empty(name, attributes, _) if name == "Value" => attributes,
                Child::Empty(..) => continue,
            };
            if let Some(index) = attr(&attributes, "Ref") {
                ref_index = Some(
                    index
                        .parse::<usize>()
                        .map_err(|_| AppError::Xml("invalid attachment ref".to_string()))?,
                );
            }
        }

        let name = match key {
            Some(value) => value,
            None => return Ok(None),
        };
        let binary = match (ref_index, value) {
            (Some(index), _) => self
                .binaries
                .get(index)
                .or_else(|| self.meta_binaries.get(&index))
                .cloned()
                .ok_or_else(|| AppError::Xml("attachment ref out of bounds".to_string()))?,
            (None, Some(binary)) => binary,
            (None, None) => PoolBinary::new(Vec::new(), true),
        };
        Ok(Some(Attachment::with_protection(
            name,
            binary.data.to_vec(),
            binary.protected,
        )))
    }
}

fn attrs(element: &BytesStart) -> Vec<(String, String)> {
    element
        .attributes()
        .flatten()
        .map(|attribute| (attribute.key.0.to_string(), attribute.value.into_owned()))
        .collect()
}

fn attr(attributes: &[(String, String)], key: &str) -> Option<String> {
    attributes
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
}

/// Resolve an entity or character reference (`&amp;`, `&#13;`) in text.
fn resolve_reference(reference: &BytesRef) -> AppResult<char> {
    if let Some(ch) = reference
        .resolve_char_ref()
        .map_err(|_| AppError::Xml("invalid character reference".to_string()))?
    {
        return Ok(ch);
    }
    match &*reference.xml10_content() {
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "amp" => Ok('&'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        other => Err(AppError::Xml(format!("unknown entity &{other};"))),
    }
}

fn decode_base64(text: &str, what: &str) -> AppResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|_| AppError::Xml(format!("invalid {what} base64")))
}

/// Parse a base64 UUID; the all-zero UUID, which KeePassXC writes for
/// "none", is `None`.
fn parse_uuid(text: &str) -> AppResult<Option<Uuid>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let decoded = decode_base64(text, "UUID")?;
    let uuid =
        Uuid::from_slice(&decoded).map_err(|_| AppError::Xml("invalid UUID bytes".to_string()))?;
    Ok((!uuid.is_nil()).then_some(uuid))
}

fn parse_bool(text: &str, default: bool) -> bool {
    match text.trim() {
        value if value.eq_ignore_ascii_case("true") => true,
        value if value.eq_ignore_ascii_case("false") => false,
        _ => default,
    }
}

// ─── Writing ────────────────────────────────────────────────────────────────

struct WriteContext<'a> {
    stream: &'a mut ProtectedStream,
    index: &'a PoolIndex,
    protect_fields: bool,
    memory_protection: MemoryProtection,
    /// KDBX4 time encoding and 4.1 elements; see [`BinaryPool`].
    kdbx4: bool,
}

/// Pool position of each distinct (data, protection flag) pair.
type PoolIndex = HashMap<(Vec<u8>, bool), usize>;

fn pool_key(attachment: &Attachment) -> (Vec<u8>, bool) {
    (attachment.data().to_vec(), attachment.protected())
}

/// The database's `Meta/MemoryProtection` settings: which standard fields
/// are always written protected, whatever each entry says.
#[derive(Debug, Clone, Copy)]
struct MemoryProtection {
    title: bool,
    username: bool,
    password: bool,
    url: bool,
    notes: bool,
}

impl MemoryProtection {
    /// Read the settings, using KeePassXC's defaults (only the password) for
    /// anything missing.
    fn of(database: &Database) -> Self {
        let raw = database
            .meta()
            .extra()
            .iter()
            .find(|raw| raw.name() == "MemoryProtection");
        let flag = |tag: &str, default: bool| {
            raw.and_then(|raw| crate::model::element_text(raw.xml(), tag))
                .map_or(default, |text| text.trim().eq_ignore_ascii_case("true"))
        };
        Self {
            title: flag("ProtectTitle", false),
            username: flag("ProtectUserName", false),
            password: flag("ProtectPassword", true),
            url: flag("ProtectURL", false),
            notes: flag("ProtectNotes", false),
        }
    }

    fn covers(self, key: &str) -> bool {
        match key {
            "Title" => self.title,
            "UserName" => self.username,
            "Password" => self.password,
            "URL" => self.url,
            "Notes" => self.notes,
            _ => false,
        }
    }
}

/// Collect every attachment (including those in history) into a deduplicated pool.
fn build_attachment_pool(root: &Group) -> (Vec<PoolBinary>, PoolIndex) {
    fn visit_entry(entry: &Entry, pool: &mut Vec<PoolBinary>, index: &mut PoolIndex) {
        for attachment in entry.attachments() {
            let key = pool_key(attachment);
            if let std::collections::hash_map::Entry::Vacant(slot) = index.entry(key) {
                slot.insert(pool.len());
                pool.push(PoolBinary::new(
                    attachment.data().to_vec(),
                    attachment.protected(),
                ));
            }
        }
        for item in entry.history() {
            visit_entry(item, pool, index);
        }
    }
    fn visit_group(group: &Group, pool: &mut Vec<PoolBinary>, index: &mut PoolIndex) {
        for entry in group.entries() {
            visit_entry(entry, pool, index);
        }
        for child in group.groups() {
            visit_group(child, pool, index);
        }
    }
    let mut pool = Vec::new();
    let mut index = HashMap::new();
    visit_group(root, &mut pool, &mut index);
    (pool, index)
}

fn xml_write_error(err: std::io::Error) -> AppError {
    AppError::Xml(format!("xml write error: {err}"))
}

fn start<W: std::io::Write>(writer: &mut Writer<W>, element: BytesStart) -> AppResult<()> {
    writer
        .write_event(Event::Start(element))
        .map_err(xml_write_error)?;
    Ok(())
}

fn end<W: std::io::Write>(writer: &mut Writer<W>, name: &str) -> AppResult<()> {
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(xml_write_error)?;
    Ok(())
}

/// Write preserved elements back unchanged.
fn write_raw<W: std::io::Write>(writer: &mut Writer<W>, elements: &[RawElement]) -> AppResult<()> {
    for element in elements {
        writer
            .write_event(Event::Text(BytesText::from_escaped(element.xml())))
            .map_err(xml_write_error)?;
    }
    Ok(())
}

fn write_meta<W: std::io::Write>(
    writer: &mut Writer<W>,
    database: &Database,
    binaries: &[PoolBinary],
    header_hash: Option<&[u8]>,
    kdbx4: bool,
) -> AppResult<()> {
    start(writer, BytesStart::new("Meta"))?;
    write_simple_element(writer, "Generator", "keepassxcr")?;
    if let Some(hash) = header_hash {
        let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
        write_simple_element(writer, "HeaderHash", &encoded)?;
    }
    write_simple_element(writer, "DatabaseName", database.meta().name())?;
    write_simple_element(writer, "DatabaseDescription", database.meta().description())?;
    let meta = database.meta();
    if !meta.custom_icons().is_empty() {
        start(writer, BytesStart::new("CustomIcons"))?;
        write_raw(writer, meta.custom_icons())?;
        end(writer, "CustomIcons")?;
    }
    write_bool(writer, "RecycleBinEnabled", meta.recycle_bin_enabled())?;
    write_uuid_element(
        writer,
        "RecycleBinUUID",
        meta.recycle_bin().unwrap_or(Uuid::nil()),
    )?;
    write_time(
        writer,
        "RecycleBinChanged",
        meta.recycle_bin_changed(),
        kdbx4,
    )?;
    let limits = meta.history_limits();
    write_simple_element(writer, "HistoryMaxItems", &limits.max_items.to_string())?;
    write_simple_element(writer, "HistoryMaxSize", &limits.max_size.to_string())?;
    write_raw(writer, meta.extra())?;

    if !binaries.is_empty() {
        start(writer, BytesStart::new("Binaries"))?;
        for (id, binary) in binaries.iter().enumerate() {
            let mut element = BytesStart::new("Binary");
            element.push_attribute(("ID", id.to_string().as_str()));
            let encoded = base64::engine::general_purpose::STANDARD.encode(&binary.data[..]);
            write_text_element(writer, "Binary", element, &encoded)?;
        }
        end(writer, "Binaries")?;
    }

    end(writer, "Meta")
}

fn write_group<W: std::io::Write>(
    writer: &mut Writer<W>,
    group: &Group,
    ctx: &mut WriteContext,
) -> AppResult<()> {
    start(writer, BytesStart::new("Group"))?;
    write_uuid(writer, group.uuid())?;
    write_simple_element(writer, "Name", group.name())?;
    // Group tags and the previous parent are KDBX 4.1 only.
    if ctx.kdbx4 && !group.tags().is_empty() {
        write_simple_element(writer, "Tags", group.tags())?;
    }
    write_times(writer, group.times(), ctx.kdbx4)?;
    if ctx.kdbx4
        && let Some(previous) = group.previous_parent_group()
    {
        write_uuid_element(writer, "PreviousParentGroup", previous)?;
    }
    write_raw(writer, group.extra())?;

    for entry in group.entries() {
        write_entry(writer, entry, ctx, true)?;
    }
    for child in group.groups() {
        write_group(writer, child, ctx)?;
    }
    end(writer, "Group")
}

fn write_entry<W: std::io::Write>(
    writer: &mut Writer<W>,
    entry: &Entry,
    ctx: &mut WriteContext,
    with_history: bool,
) -> AppResult<()> {
    start(writer, BytesStart::new("Entry"))?;
    write_uuid(writer, entry.uuid())?;
    if !entry.tags().is_empty() {
        write_simple_element(writer, "Tags", &entry.tags().join(","))?;
    }
    write_times(writer, entry.times(), ctx.kdbx4)?;
    if ctx.kdbx4
        && let Some(previous) = entry.previous_parent_group()
    {
        write_uuid_element(writer, "PreviousParentGroup", previous)?;
    }
    write_raw(writer, entry.extra())?;

    // Like KeePassXC: a field is protected if the entry says so or the
    // database's memory-protection settings cover it.
    let standard = [
        ("Title", entry.title()),
        ("UserName", entry.username()),
        ("Password", entry.password().expose_secret()),
        ("URL", entry.url()),
        ("Notes", entry.notes()),
    ];
    let custom = entry
        .custom_fields()
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()));
    for (key, value) in standard.into_iter().chain(custom) {
        let protected = entry.protected_fields().contains(key) || ctx.memory_protection.covers(key);
        write_string(writer, key, value, protected, ctx)?;
    }

    for attachment in entry.attachments() {
        let index = ctx
            .index
            .get(&pool_key(attachment))
            .copied()
            .ok_or_else(|| AppError::Xml("attachment missing from pool".to_string()))?;
        write_attachment_ref(writer, attachment.name(), index)?;
    }

    if with_history && !entry.history().is_empty() {
        start(writer, BytesStart::new("History"))?;
        for item in entry.history() {
            write_entry(writer, item, ctx, false)?;
        }
        end(writer, "History")?;
    }

    end(writer, "Entry")
}

fn write_string<W: std::io::Write>(
    writer: &mut Writer<W>,
    key: &str,
    value: &str,
    protect: bool,
    ctx: &mut WriteContext,
) -> AppResult<()> {
    start(writer, BytesStart::new("String"))?;
    write_simple_element(writer, "Key", key)?;

    let mut value_element = BytesStart::new("Value");
    if protect && ctx.protect_fields {
        value_element.push_attribute(("Protected", "True"));
        let mut content = value.as_bytes().to_vec();
        ctx.stream.apply(&mut content)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(content);
        write_text_element(writer, "Value", value_element, &encoded)?;
    } else {
        write_text_element(writer, "Value", value_element, value)?;
    }

    end(writer, "String")
}

fn write_attachment_ref<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: &str,
    index: usize,
) -> AppResult<()> {
    start(writer, BytesStart::new("Binary"))?;
    write_simple_element(writer, "Key", name)?;
    let mut value_element = BytesStart::new("Value");
    value_element.push_attribute(("Ref", index.to_string().as_str()));
    writer
        .write_event(Event::Empty(value_element))
        .map_err(xml_write_error)?;
    end(writer, "Binary")
}

fn write_uuid<W: std::io::Write>(writer: &mut Writer<W>, uuid: Uuid) -> AppResult<()> {
    write_uuid_element(writer, "UUID", uuid)
}

fn write_uuid_element<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: &str,
    uuid: Uuid,
) -> AppResult<()> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(uuid.as_bytes());
    write_simple_element(writer, name, &encoded)
}

fn write_bool<W: std::io::Write>(writer: &mut Writer<W>, name: &str, value: bool) -> AppResult<()> {
    write_simple_element(writer, name, if value { "True" } else { "False" })
}

/// Write a time as KeePassXC does: base64 seconds for KDBX4, ISO 8601 for KDBX3.
fn write_time<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: &str,
    time: Timestamp,
    kdbx4: bool,
) -> AppResult<()> {
    let text = if kdbx4 {
        time.to_base64()
    } else {
        time.to_iso()
    };
    write_simple_element(writer, name, &text)
}

fn write_deleted_objects<W: std::io::Write>(
    writer: &mut Writer<W>,
    deleted: &[DeletedObject],
    kdbx4: bool,
) -> AppResult<()> {
    if deleted.is_empty() {
        return Ok(());
    }
    start(writer, BytesStart::new("DeletedObjects"))?;
    for object in deleted {
        start(writer, BytesStart::new("DeletedObject"))?;
        write_uuid(writer, object.uuid)?;
        write_time(writer, "DeletionTime", object.deletion_time, kdbx4)?;
        end(writer, "DeletedObject")?;
    }
    end(writer, "DeletedObjects")
}

fn write_times<W: std::io::Write>(
    writer: &mut Writer<W>,
    times: &Times,
    kdbx4: bool,
) -> AppResult<()> {
    start(writer, BytesStart::new("Times"))?;
    write_time(writer, "CreationTime", times.creation, kdbx4)?;
    write_time(
        writer,
        "LastModificationTime",
        times.last_modification,
        kdbx4,
    )?;
    write_time(writer, "LastAccessTime", times.last_access, kdbx4)?;
    write_time(writer, "ExpiryTime", times.expiry, kdbx4)?;
    write_bool(writer, "Expires", times.expires)?;
    write_simple_element(writer, "UsageCount", &times.usage_count.to_string())?;
    write_time(writer, "LocationChanged", times.location_changed, kdbx4)?;
    end(writer, "Times")
}

fn write_simple_element<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: &str,
    value: &str,
) -> AppResult<()> {
    write_text_element(writer, name, BytesStart::new(name), value)
}

fn write_text_element<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: &str,
    element: BytesStart,
    value: &str,
) -> AppResult<()> {
    // An empty value must be a self-closing tag: with indentation, a separate
    // end tag would put whitespace inside the element and change the value.
    if value.is_empty() {
        writer
            .write_event(Event::Empty(element))
            .map_err(xml_write_error)?;
        return Ok(());
    }
    start(writer, element)?;
    writer
        .write_event(Event::Text(BytesText::new(value)))
        .map_err(xml_write_error)?;
    end(writer, name)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    const KEY: [u8; 32] = [1u8; 32];

    fn roundtrip(db: &Database, pool: BinaryPool) -> Database {
        let output = write_database(db, &KEY, ProtectedStreamAlgo::Salsa20, true, pool, None)
            .expect("write");
        read_database(
            &output.xml,
            &output.attachments,
            &KEY,
            ProtectedStreamAlgo::Salsa20,
            None,
        )
        .expect("read")
    }

    #[test]
    fn xml_roundtrip_basic() {
        let mut db = Database::new("Root".to_string());
        db.meta_mut().set_name("Test".to_string());
        db.root_mut()
            .entries_mut()
            .push(Entry::new("Entry".to_string()));
        let parsed = roundtrip(&db, BinaryPool::InnerHeader);
        assert_eq!(parsed.meta().name(), "Test");
    }

    #[test]
    fn history_does_not_replace_current_values() {
        let mut entry = Entry::new("Bank".to_string());
        entry.set_password(SecretString::new("old".to_string()));
        entry.begin_update(HistoryLimits::default());
        entry.set_password(SecretString::new("current".to_string()));
        let mut db = Database::new("Root".to_string());
        db.root_mut().entries_mut().push(entry);

        let parsed = roundtrip(&db, BinaryPool::InnerHeader);
        let entries = parsed.root().entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].password().expose_secret(), "current");
        assert_eq!(entries[0].history().len(), 1);
        assert_eq!(entries[0].history()[0].password().expose_secret(), "old");
    }

    #[test]
    fn unknown_elements_are_preserved() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile><Meta><DatabaseName>DB</DatabaseName><RecycleBinEnabled>True</RecycleBinEnabled></Meta>
<Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>Root</Name><Notes>group notes</Notes>
<Entry><UUID>AQEBAQEBAQEBAQEBAQEBAQ==</UUID><Tags>a;b</Tags><Times><Expires>True</Expires></Times>
<String><Key>Title</Key><Value>E</Value></String><AutoType><Enabled>True</Enabled></AutoType></Entry>
</Group><DeletedObjects><DeletedObject><UUID>AgICAgICAgICAgICAgICAg==</UUID><DeletionTime>2024-01-01T00:00:00Z</DeletionTime></DeletedObject></DeletedObjects></Root></KeePassFile>"#;
        let db = read_database(xml, &[], &KEY, ProtectedStreamAlgo::Salsa20, None).expect("read");
        let output = write_database(
            &db,
            &KEY,
            ProtectedStreamAlgo::Salsa20,
            true,
            BinaryPool::InnerHeader,
            None,
        )
        .expect("write");
        let text = String::from_utf8(output.xml).expect("utf8");
        for needle in [
            "<RecycleBinEnabled>True</RecycleBinEnabled>",
            "<Notes>group notes</Notes>",
            "<Tags>a,b</Tags>",
            "<Expires>True</Expires>",
            "<AutoType><Enabled>True</Enabled></AutoType>",
            "<DeletedObject>",
            "<UUID>AgICAgICAgICAgICAgICAg==</UUID>",
        ] {
            assert!(text.contains(needle), "missing {needle} in {text}");
        }
    }

    #[test]
    fn attachments_roundtrip_in_both_pools() {
        let mut entry = Entry::new("E".to_string());
        entry
            .attachments_mut()
            .push(Attachment::new("a.txt".to_string(), b"hello".to_vec()));
        entry.begin_update(HistoryLimits::default());
        let mut db = Database::new("Root".to_string());
        db.root_mut().entries_mut().push(entry);

        for pool in [BinaryPool::InnerHeader, BinaryPool::Meta] {
            let output = write_database(&db, &KEY, ProtectedStreamAlgo::Salsa20, true, pool, None)
                .expect("write");
            // The attachment is shared with the history item, so it is stored once.
            if pool == BinaryPool::InnerHeader {
                assert_eq!(output.attachments.len(), 1);
            }
            let parsed = roundtrip(&db, pool);
            let attachment = &parsed.root().entries()[0].attachments()[0];
            assert_eq!(attachment.data(), b"hello");
        }
    }

    #[test]
    fn empty_values_stay_empty() {
        let mut entry = Entry::new("E".to_string());
        entry.set_custom_field("Empty".to_string(), String::new(), false);
        let mut db = Database::new("Root".to_string());
        db.root_mut().entries_mut().push(entry);
        let output = write_database(
            &db,
            &KEY,
            ProtectedStreamAlgo::Salsa20,
            true,
            BinaryPool::Meta,
            None,
        )
        .expect("write");
        let text = String::from_utf8(output.xml).expect("utf8");
        assert!(text.contains("<Value/>"), "{text}");
        let parsed = roundtrip(&db, BinaryPool::Meta);
        let entry = &parsed.root().entries()[0];
        assert_eq!(entry.url(), "");
        assert_eq!(
            entry
                .custom_fields()
                .get("Empty")
                .map(|value| value.as_str()),
            Some("")
        );
    }

    fn parse(xml: &str) -> AppResult<Database> {
        read_database(
            xml.as_bytes(),
            &[],
            &KEY,
            ProtectedStreamAlgo::Salsa20,
            None,
        )
    }

    #[test]
    fn huge_binary_ids_do_not_panic_or_allocate() {
        for id in ["18446744073709551615", "200000000000", "40000000"] {
            let xml = format!(
                "<KeePassFile><Meta><Binaries><Binary ID=\"{id}\">aGk=</Binary></Binaries></Meta>\
                 <Root><Group><Name>R</Name><Entry><Binary><Key>a</Key><Value Ref=\"{id}\"/></Binary>\
                 </Entry></Group></Root></KeePassFile>"
            );
            let db = parse(&xml).expect("parse");
            assert_eq!(db.root().entries()[0].attachments()[0].data(), b"hi");
        }
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_stack_overflow() {
        let depth = 200_000;
        let xml = format!(
            "<KeePassFile><Root>{}{}</Root></KeePassFile>",
            "<Group>".repeat(depth),
            "</Group>".repeat(depth)
        );
        let err = parse(&xml).expect_err("too deep");
        assert!(err.to_string().contains("nested too deeply"), "{err}");

        let ok = format!(
            "<KeePassFile><Root>{}{}</Root></KeePassFile>",
            "<Group>".repeat(MAX_DEPTH),
            "</Group>".repeat(MAX_DEPTH)
        );
        parse(&ok).expect("deep but allowed");
    }

    #[test]
    fn many_attributes_parse_quickly() {
        // quick-xml before 0.41 checked duplicate attributes in quadratic time
        // (RUSTSEC-2026-0194).
        let attributes: String = (0..60_000).map(|i| format!(" a{i}=\"x\"")).collect();
        let xml = format!(
            "<KeePassFile><Root><Group{attributes}><Name>R</Name></Group></Root></KeePassFile>"
        );
        let started = std::time::Instant::now();
        parse(&xml).expect("parse");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn references_are_resolved_in_text() {
        let db = parse(
            "<KeePassFile><Root><Group><Name>a &amp; b &lt;c&gt; &#65;&#x42;</Name></Group></Root></KeePassFile>",
        )
        .expect("parse");
        assert_eq!(db.root().name(), "a & b <c> AB");
    }

    fn written(db: &Database) -> String {
        let output = write_database(
            db,
            &KEY,
            ProtectedStreamAlgo::Salsa20,
            true,
            BinaryPool::InnerHeader,
            None,
        )
        .expect("write");
        String::from_utf8(output.xml).expect("utf8")
    }

    #[test]
    fn protection_flags_survive_a_save() {
        // Notes protected per entry; the password left unprotected on purpose.
        let mut stream = ProtectedStream::new(ProtectedStreamAlgo::Salsa20, &KEY).expect("stream");
        let mut secret = b"secret notes".to_vec();
        stream.apply(&mut secret).expect("encrypt");
        let notes = base64::engine::general_purpose::STANDARD.encode(secret);
        let xml = format!(
            "<KeePassFile><Meta><MemoryProtection><ProtectPassword>False</ProtectPassword>\
             </MemoryProtection></Meta><Root><Group><Name>R</Name><Entry>\
             <String><Key>Title</Key><Value>T</Value></String>\
             <String><Key>Notes</Key><Value Protected=\"True\">{notes}</Value></String>\
             <String><Key>Password</Key><Value>plain</Value></String>\
             </Entry></Group></Root></KeePassFile>"
        );
        let db = parse(&xml).expect("parse");
        let entry = &db.root().entries()[0];
        assert_eq!(entry.notes(), "secret notes");
        assert!(entry.protected_fields().contains("Notes"));
        assert!(!entry.protected_fields().contains("Password"));

        let text = written(&db);
        assert!(!text.contains("secret notes"), "{text}");
        assert!(text.contains("<Value>plain</Value>"), "{text}");
        let reread = parse(&text).expect("reread");
        assert_eq!(reread.root().entries()[0].notes(), "secret notes");
    }

    #[test]
    fn memory_protection_settings_apply_to_every_entry() {
        let mut db = parse(
            "<KeePassFile><Meta><MemoryProtection><ProtectTitle>True</ProtectTitle>\
             </MemoryProtection></Meta><Root><Group><Name>R</Name></Group></Root></KeePassFile>",
        )
        .expect("parse");
        let mut entry = Entry::new("hidden title".to_string());
        entry.set_password(SecretString::new("hidden password".to_string()));
        db.root_mut().entries_mut().push(entry);
        let text = written(&db);
        assert!(!text.contains("hidden title"), "{text}");
        assert!(!text.contains("hidden password"), "{text}");
    }

    #[test]
    fn debug_output_hides_secrets() {
        let mut entry = Entry::new("Title".to_string());
        entry.set_password(SecretString::new("hunter2".to_string()));
        entry.set_custom_field("Token".to_string(), "abc123".to_string(), true);
        let debug = format!("{entry:?}");
        assert!(
            !debug.contains("hunter2") && !debug.contains("abc123"),
            "{debug}"
        );
    }

    #[test]
    fn times_tags_and_deletions_survive_a_save() {
        let mut db = Database::new("Root".to_string());
        let mut entry = Entry::new("E".to_string());
        entry.set_tags("b;a");
        entry.times_mut().creation = Timestamp::from_secs(63_000_000_000);
        entry.times_mut().expires = true;
        entry.times_mut().usage_count = 7;
        let previous = Uuid::new_v4();
        entry.set_previous_parent_group(Some(previous));
        let mut group = Group::new("G".to_string());
        group.set_tags("x".to_string());
        group.times_mut().expiry = Timestamp::from_secs(1);
        group.entries_mut().push(entry);
        db.root_mut().groups_mut().push(group);
        let gone = Uuid::new_v4();
        db.deleted_objects_mut().push(DeletedObject {
            uuid: gone,
            deletion_time: Timestamp::from_secs(63_800_000_000),
        });
        let bin = Uuid::new_v4();
        db.meta_mut().set_recycle_bin(Some(bin));
        db.meta_mut().set_recycle_bin_enabled(false);
        db.meta_mut().set_history_limits(HistoryLimits {
            max_items: 3,
            max_size: -1,
        });

        for pool in [BinaryPool::InnerHeader, BinaryPool::Meta] {
            let parsed = roundtrip(&db, pool);
            let group = &parsed.root().groups()[0];
            let entry = &group.entries()[0];
            assert_eq!(entry.tags(), ["a", "b"]);
            assert_eq!(entry.times(), db.root().groups()[0].entries()[0].times());
            assert_eq!(group.times().expiry, Timestamp::from_secs(1));
            assert_eq!(parsed.deleted_objects(), db.deleted_objects());
            assert_eq!(parsed.meta().recycle_bin(), Some(bin));
            assert!(!parsed.meta().recycle_bin_enabled());
            assert_eq!(parsed.meta().history_limits().max_items, 3);
            assert_eq!(parsed.meta().history_limits().max_size, -1);
            // 4.1 elements are only written to KDBX4.
            let kdbx4 = pool == BinaryPool::InnerHeader;
            assert_eq!(entry.previous_parent_group().is_some(), kdbx4);
            assert_eq!(group.tags() == "x", kdbx4);
        }

        let text = written(&db);
        let creation = Timestamp::from_secs(63_000_000_000).to_base64();
        assert!(
            text.contains(&format!("<CreationTime>{creation}</CreationTime>")),
            "{text}"
        );
    }

    #[test]
    fn keepassxc_times_in_both_encodings_are_read() {
        let db = parse(
            "<KeePassFile><Root><Group><Name>R</Name>\
             <Times><LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime>\
             <Expires>True</Expires><Bogus>1</Bogus></Times>\
             <Entry><Times><LastModificationTime>AAAAAAAAAAA=</LastModificationTime>\
             <UsageCount>3</UsageCount></Times></Entry>\
             </Group></Root></KeePassFile>",
        )
        .expect("parse");
        let root = db.root();
        assert_eq!(
            root.times().last_modification.to_iso(),
            "2024-01-01T00:00:00Z"
        );
        assert!(root.times().expires);
        assert_eq!(root.entries()[0].times().last_modification.secs(), 0);
        assert_eq!(root.entries()[0].times().usage_count, 3);
    }
}
