//! KeePass XML parser and writer.

use std::io::Cursor;

use base64::Engine as _;
use quick_xml::Reader;
use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use secrecy::ExposeSecret;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::crypto::{ProtectedStream, ProtectedStreamAlgo};
use crate::error::{AppError, AppResult};
use crate::model::{Attachment, Database, Entry, Group};

/// XML output with attachment pool.
#[derive(Debug, Clone)]
pub struct XmlOutput {
    /// Serialized XML bytes.
    pub xml: Vec<u8>,
    /// Attachment pool in the order written.
    pub attachments: Vec<Vec<u8>>,
}

/// Parse a KeePass XML document into a database.
pub fn read_database(
    xml: &[u8],
    attachments: &[Vec<u8>],
    protected_stream_key: &[u8],
    algo: ProtectedStreamAlgo,
) -> AppResult<Database> {
    let mut reader = Reader::from_reader(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut db_name = "Database".to_string();
    let mut db_description = String::new();
    let mut root_group = None;
    let mut stream = ProtectedStream::new(algo, protected_stream_key)?;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Meta" => {
                parse_meta(&mut reader, &mut db_name, &mut db_description)?;
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Root" => {
                root_group = Some(parse_root(&mut reader, &mut stream, attachments)?);
            }
            Ok(Event::Eof) => break,
            Err(err) => {
                return Err(AppError::Xml(format!("xml parse error: {err}")));
            }
            _ => {}
        }
        buf.clear();
    }

    let mut database = Database::new(db_name.clone());
    database.meta_mut().set_name(db_name);
    database.meta_mut().set_description(db_description);
    if let Some(group) = root_group {
        *database.root_mut() = group;
    }

    Ok(database)
}

/// Serialize a database to KeePass XML.
pub fn write_database(
    database: &Database,
    protected_stream_key: &[u8],
    algo: ProtectedStreamAlgo,
    protect_fields: bool,
) -> AppResult<XmlOutput> {
    let mut output = Vec::new();
    let mut writer = Writer::new_with_indent(Cursor::new(&mut output), b' ', 4);
    let mut stream = ProtectedStream::new(algo, protected_stream_key)?;
    let mut attachments = Vec::new();

    writer
        .write_event(Event::Decl(quick_xml::events::BytesDecl::new(
            "1.0",
            Some("UTF-8"),
            None,
        )))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    writer
        .write_event(Event::Start(BytesStart::new("KeePassFile")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    write_meta(&mut writer, database)?;
    write_root(
        &mut writer,
        database.root(),
        &mut stream,
        &mut attachments,
        protect_fields,
    )?;

    writer
        .write_event(Event::End(BytesEnd::new("KeePassFile")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    Ok(XmlOutput {
        xml: output,
        attachments,
    })
}

fn parse_meta(
    reader: &mut Reader<&[u8]>,
    name: &mut String,
    description: &mut String,
) -> AppResult<()> {
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"DatabaseName" => {
                *name = read_text(reader)?;
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"DatabaseDescription" => {
                *description = read_text(reader)?;
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"Meta" => break,
            Ok(Event::Eof) => break,
            Err(err) => return Err(AppError::Xml(format!("xml meta error: {err}"))),
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn parse_root(
    reader: &mut Reader<&[u8]>,
    stream: &mut ProtectedStream,
    attachments: &[Vec<u8>],
) -> AppResult<Group> {
    let mut buf = Vec::new();
    let mut root_group = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Group" => {
                root_group = Some(parse_group(reader, stream, attachments)?);
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"Root" => break,
            Ok(Event::Eof) => break,
            Err(err) => return Err(AppError::Xml(format!("xml root error: {err}"))),
            _ => {}
        }
        buf.clear();
    }

    root_group.ok_or_else(|| AppError::Xml("missing root group".to_string()))
}

fn parse_group(
    reader: &mut Reader<&[u8]>,
    stream: &mut ProtectedStream,
    attachments: &[Vec<u8>],
) -> AppResult<Group> {
    let mut buf = Vec::new();
    let mut name = "Group".to_string();
    let mut uuid = None;
    let mut entries = Vec::new();
    let mut groups = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"UUID" => {
                uuid = Some(parse_uuid(&read_text(reader)?)?);
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Name" => {
                name = read_text(reader)?;
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Entry" => {
                entries.push(parse_entry(reader, stream, attachments)?);
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Group" => {
                groups.push(parse_group(reader, stream, attachments)?);
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"Group" => break,
            Ok(Event::Eof) => break,
            Err(err) => return Err(AppError::Xml(format!("xml group error: {err}"))),
            _ => {}
        }
        buf.clear();
    }

    let mut group = match uuid {
        Some(value) => Group::with_uuid(value, name),
        None => Group::new(name),
    };
    *group.groups_mut() = groups;
    *group.entries_mut() = entries;
    Ok(group)
}

fn parse_entry(
    reader: &mut Reader<&[u8]>,
    stream: &mut ProtectedStream,
    attachments: &[Vec<u8>],
) -> AppResult<Entry> {
    let mut buf = Vec::new();
    let mut uuid = None;
    let mut title = "Entry".to_string();
    let mut username = None;
    let mut password = None;
    let mut url = None;
    let mut notes = None;
    let mut custom = Vec::new();
    let mut entry_attachments = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"UUID" => {
                uuid = Some(parse_uuid(&read_text(reader)?)?);
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"String" => {
                let (key, value, protected) = parse_string(reader, stream)?;
                match key.as_str() {
                    "Title" => title = value,
                    "UserName" => username = Some(value),
                    "Password" => {
                        password = Some(value);
                    }
                    "URL" => url = Some(value),
                    "Notes" => notes = Some(value),
                    _ => custom.push((key, value, protected)),
                }
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Binary" => {
                if let Some(attachment) = parse_binary(reader, attachments)? {
                    entry_attachments.push(attachment);
                }
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"Entry" => break,
            Ok(Event::Eof) => break,
            Err(err) => return Err(AppError::Xml(format!("xml entry error: {err}"))),
            _ => {}
        }
        buf.clear();
    }

    let mut entry = match uuid {
        Some(value) => Entry::with_uuid(value, title),
        None => Entry::new(title),
    };
    if let Some(value) = username {
        entry.set_username(value);
    }
    if let Some(value) = password {
        entry.set_password(secrecy::SecretString::new(value));
    }
    if let Some(value) = url {
        entry.set_url(value);
    }
    if let Some(value) = notes {
        entry.set_notes(value);
    }
    for (key, value, protected) in custom {
        entry.set_custom_field(key, value, protected);
    }
    for attachment in entry_attachments {
        entry.attachments_mut().push(attachment);
    }
    Ok(entry)
}

fn parse_string(
    reader: &mut Reader<&[u8]>,
    stream: &mut ProtectedStream,
) -> AppResult<(String, String, bool)> {
    let mut buf = Vec::new();
    let mut key = String::new();
    let mut value = String::new();
    let mut protected = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Key" => {
                key = read_text(reader)?;
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Value" => {
                let is_protected = e.attributes().flatten().any(|attr| {
                    attr.key.as_ref() == b"Protected" && attr.value.as_ref() == b"True"
                });
                let protect_in_memory = e.attributes().flatten().any(|attr| {
                    attr.key.as_ref() == b"ProtectInMemory" && attr.value.as_ref() == b"True"
                });
                protected = is_protected || protect_in_memory;
                let raw = read_text(reader)?;
                if is_protected {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(raw.as_bytes())
                        .map_err(|_| AppError::Xml("invalid protected base64".to_string()))?;
                    let mut bytes = decoded.clone();
                    stream.apply(&mut bytes)?;
                    value = String::from_utf8(bytes)
                        .map_err(|_| AppError::Xml("invalid protected utf8".to_string()))?;
                } else {
                    value = raw;
                }
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"String" => break,
            Ok(Event::Eof) => break,
            Err(err) => return Err(AppError::Xml(format!("xml string error: {err}"))),
            _ => {}
        }
        buf.clear();
    }

    Ok((key, value, protected))
}

fn parse_binary(
    reader: &mut Reader<&[u8]>,
    attachments: &[Vec<u8>],
) -> AppResult<Option<Attachment>> {
    let mut buf = Vec::new();
    let mut key = None;
    let mut value = None;
    let mut ref_index = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Key" => {
                key = Some(read_text(reader)?);
            }
            Ok(Event::Start(ref e)) if e.name().as_ref() == b"Value" => {
                for attr in e.attributes().flatten() {
                    if attr.key.as_ref() == b"Ref" {
                        let idx = std::str::from_utf8(attr.value.as_ref())
                            .map_err(|_| AppError::Xml("invalid attachment ref".to_string()))?;
                        ref_index =
                            Some(idx.parse::<usize>().map_err(|_| {
                                AppError::Xml("invalid attachment ref".to_string())
                            })?);
                    }
                }
                let raw = read_text(reader)?;
                if !raw.is_empty() {
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(raw.as_bytes())
                        .map_err(|_| AppError::Xml("invalid attachment base64".to_string()))?;
                    value = Some(decoded);
                }
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"Binary" => break,
            Ok(Event::Eof) => break,
            Err(err) => return Err(AppError::Xml(format!("xml binary error: {err}"))),
            _ => {}
        }
        buf.clear();
    }

    let name = match key {
        Some(value) => value,
        None => return Ok(None),
    };
    let data = if let Some(index) = ref_index {
        attachments
            .get(index)
            .cloned()
            .ok_or_else(|| AppError::Xml("attachment ref out of bounds".to_string()))?
    } else {
        value.ok_or_else(|| AppError::Xml("missing attachment data".to_string()))?
    };

    Ok(Some(Attachment::new(name, data)))
}

fn read_text(reader: &mut Reader<&[u8]>) -> AppResult<String> {
    let mut buf = Vec::new();
    let mut text = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Text(e)) => {
                text = e
                    .unescape()
                    .map_err(|_| AppError::Xml("invalid text".to_string()))?
                    .to_string();
            }
            Ok(Event::End(_)) => break,
            Ok(Event::Eof) => break,
            Err(err) => return Err(AppError::Xml(format!("xml text error: {err}"))),
            _ => {}
        }
        buf.clear();
    }
    Ok(text)
}

fn parse_uuid(text: &str) -> AppResult<Uuid> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.as_bytes())
        .map_err(|_| AppError::Xml("invalid UUID base64".to_string()))?;
    Uuid::from_slice(&decoded).map_err(|_| AppError::Xml("invalid UUID bytes".to_string()))
}

fn write_meta<W: std::io::Write>(writer: &mut Writer<W>, database: &Database) -> AppResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("Meta")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    write_simple_element(writer, "Generator", "keepassxcr")?;
    write_simple_element(writer, "DatabaseName", database.meta().name())?;
    write_simple_element(writer, "DatabaseDescription", database.meta().description())?;

    writer
        .write_event(Event::End(BytesEnd::new("Meta")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
}

fn write_root<W: std::io::Write>(
    writer: &mut Writer<W>,
    group: &Group,
    stream: &mut ProtectedStream,
    attachments: &mut Vec<Vec<u8>>,
    protect_fields: bool,
) -> AppResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("Root")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    write_group(writer, group, stream, attachments, protect_fields)?;

    writer
        .write_event(Event::End(BytesEnd::new("Root")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
}

fn write_group<W: std::io::Write>(
    writer: &mut Writer<W>,
    group: &Group,
    stream: &mut ProtectedStream,
    attachments: &mut Vec<Vec<u8>>,
    protect_fields: bool,
) -> AppResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("Group")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    write_uuid(writer, group.uuid())?;
    write_simple_element(writer, "Name", group.name())?;
    write_times(writer)?;

    for entry in group.entries() {
        write_entry(writer, entry, stream, attachments, protect_fields)?;
    }
    for child in group.groups() {
        write_group(writer, child, stream, attachments, protect_fields)?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("Group")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
}

fn write_entry<W: std::io::Write>(
    writer: &mut Writer<W>,
    entry: &Entry,
    stream: &mut ProtectedStream,
    attachments: &mut Vec<Vec<u8>>,
    protect_fields: bool,
) -> AppResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("Entry")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    write_uuid(writer, entry.uuid())?;
    write_times(writer)?;

    write_string(
        writer,
        "Title",
        entry.title(),
        false,
        stream,
        protect_fields,
    )?;
    write_string(
        writer,
        "UserName",
        entry.username(),
        false,
        stream,
        protect_fields,
    )?;
    write_string(
        writer,
        "Password",
        entry.password().expose_secret(),
        true,
        stream,
        protect_fields,
    )?;
    write_string(writer, "URL", entry.url(), false, stream, protect_fields)?;
    write_string(
        writer,
        "Notes",
        entry.notes(),
        false,
        stream,
        protect_fields,
    )?;

    for (key, value) in entry.custom_fields() {
        let protected = entry.protected_fields().contains(key);
        write_string(writer, key, value, protected, stream, protect_fields)?;
    }

    for attachment in entry.attachments() {
        let index = attachments.len();
        attachments.push(attachment.data().to_vec());
        write_attachment_ref(writer, attachment.name(), index)?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("Entry")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
}

fn write_string<W: std::io::Write>(
    writer: &mut Writer<W>,
    key: &str,
    value: &str,
    protect: bool,
    stream: &mut ProtectedStream,
    protect_fields: bool,
) -> AppResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("String")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    write_simple_element(writer, "Key", key)?;

    let mut value_element = BytesStart::new("Value");
    let mut content = value.as_bytes().to_vec();
    if protect && protect_fields {
        value_element.push_attribute(("Protected", "True"));
        stream.apply(&mut content)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(content);
        write_text_element(writer, "Value", value_element, &encoded)?;
    } else {
        write_text_element(writer, "Value", value_element, value)?;
    }

    writer
        .write_event(Event::End(BytesEnd::new("String")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
}

fn write_attachment_ref<W: std::io::Write>(
    writer: &mut Writer<W>,
    name: &str,
    index: usize,
) -> AppResult<()> {
    writer
        .write_event(Event::Start(BytesStart::new("Binary")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    write_simple_element(writer, "Key", name)?;

    let mut value_element = BytesStart::new("Value");
    value_element.push_attribute(("Ref", index.to_string().as_str()));
    write_text_element(writer, "Value", value_element, "")?;

    writer
        .write_event(Event::End(BytesEnd::new("Binary")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
}

fn write_uuid<W: std::io::Write>(writer: &mut Writer<W>, uuid: Uuid) -> AppResult<()> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(uuid.as_bytes());
    write_simple_element(writer, "UUID", &encoded)
}

fn write_times<W: std::io::Write>(writer: &mut Writer<W>) -> AppResult<()> {
    let now = OffsetDateTime::now_utc();
    let formatted = now
        .format(&Rfc3339)
        .map_err(|_| AppError::Xml("time format".to_string()))?;

    writer
        .write_event(Event::Start(BytesStart::new("Times")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;

    for field in [
        "CreationTime",
        "LastModificationTime",
        "LastAccessTime",
        "ExpiryTime",
        "LocationChanged",
    ] {
        write_simple_element(writer, field, &formatted)?;
    }
    write_simple_element(writer, "Expires", "False")?;
    write_simple_element(writer, "UsageCount", "0")?;

    writer
        .write_event(Event::End(BytesEnd::new("Times")))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
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
    writer
        .write_event(Event::Start(element))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    if !value.is_empty() {
        writer
            .write_event(Event::Text(BytesText::new(value)))
            .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    }
    writer
        .write_event(Event::End(BytesEnd::new(name)))
        .map_err(|err| AppError::Xml(format!("xml write error: {err}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_roundtrip_basic() {
        let mut db = Database::new("Root".to_string());
        db.meta_mut().set_name("Test".to_string());
        db.root_mut()
            .entries_mut()
            .push(Entry::new("Entry".to_string()));

        let output =
            write_database(&db, &[1u8; 32], ProtectedStreamAlgo::Salsa20, true).expect("write");
        let parsed = read_database(
            &output.xml,
            &output.attachments,
            &[1u8; 32],
            ProtectedStreamAlgo::Salsa20,
        )
        .expect("read");
        assert_eq!(parsed.meta().name(), "Test");
    }
}
