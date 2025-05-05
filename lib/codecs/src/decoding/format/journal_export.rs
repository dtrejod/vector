use std::io::BufRead;
use std::collections::HashMap;
use std::sync::OnceLock;

use bytes::Bytes;
use chrono::{TimeZone, Utc};
use derivative::Derivative;
use lookup::{owned_value_path, OwnedTargetPath};
use smallvec::SmallVec;
use vector_config::configurable_component;
use vector_core::{
    config::{log_schema, DataType, LogNamespace},
    event::{Event, LogEvent, Value},
    schema,
};
use vrl::value::Kind;

use super::{default_lossy, Deserializer};

/// Deserializer for the systemd Journal Export Format.
///
/// This format is used for exporting journal data for transfer across the network or local IPC.
/// The format specification is documented at <https://systemd.io/JOURNAL_EXPORT_FORMATS/>.
///
/// The format consists of journal entries separated by double newlines, where each entry contains
/// fields in one of two formats:
///
/// 1. Text format: `FIELD_NAME=field value` for fields containing only valid non-control UTF-8
/// 2. Binary format: For fields containing binary or special characters:
///    ```text
///    FIELD_NAME
///    <8-byte-size-le><binary-data>
///    ```
///
/// # Vector Schema Field Mappings
///
/// The following systemd journal fields are transformed into Vector schema fields:
///
/// * `MESSAGE=` -> `message` - The main log message content
/// * `__REALTIME_TIMESTAMP=` -> `timestamp` - Event timestamp in microseconds since epoch
/// * `_HOSTNAME=` -> `host` - The name of the originating host
/// * `_SYSTEMD_UNIT=` -> `service` - The systemd unit name that generated the message
///
/// Other journal fields are preserved as-is or can be excluded based on configuration.
/// See `JournalExportDeserializerOptions` for field preservation options.
///
/// # Field Definitions
///
/// The journal supports various standard fields as documented in
/// <https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html>.
///
#[derive(Debug, Clone, Derivative)]
#[derivative(Default)]
pub struct JournalExportDeserializer {
    #[derivative(Default(value = "default_lossy()"))]
    lossy: bool,
    #[derivative(Default(value = "default_preserve_original_fields()"))]
    preserve_original_fields: bool,
}


#[derive(Debug, Clone)]
struct FieldInfo {
    field_type: FieldType,
    kind: Kind,
    meaning: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FieldType {
    Timestamp,
    Integer,
    Bytes,
}

// field definitions defines the set of fields that are supported by the journal
// export format decoder. Fields not explicitly defined are still parsed but
// will not be decoded into a known field.
fn field_definitions() -> &'static HashMap<&'static str, FieldInfo> {
    static FIELD_DEFS: OnceLock<HashMap<&'static str, FieldInfo>> = OnceLock::new();
    FIELD_DEFS.get_or_init(|| {
        let mut m = HashMap::new();

        // Core message fields
        m.insert("MESSAGE", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: Some("message"),
        });
        m.insert("PRIORITY", FieldInfo {
            field_type: FieldType::Integer,
            kind: Kind::integer(),
            meaning: None,
        });
        
        // Timestamps
        m.insert("__REALTIME_TIMESTAMP", FieldInfo {
            field_type: FieldType::Timestamp,
            kind: Kind::timestamp(),
            meaning: Some("timestamp"),
        });
        m.insert("__MONOTONIC_TIMESTAMP", FieldInfo {
            field_type: FieldType::Integer,
            kind: Kind::integer(),
            meaning: None,
        });
        
        // Process information
        m.insert("_PID", FieldInfo {
            field_type: FieldType::Integer,
            kind: Kind::integer(),
            meaning: None,
        });
        m.insert("_UID", FieldInfo {
            field_type: FieldType::Integer,
            kind: Kind::integer(),
            meaning: None,
        });
        m.insert("_GID", FieldInfo {
            field_type: FieldType::Integer,
            kind: Kind::integer(),
            meaning: None,
        });
        m.insert("_COMM", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });
        m.insert("_EXE", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });
        m.insert("_CMDLINE", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });

        // Host and boot information
        m.insert("_HOSTNAME", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: Some("host"),
        });
        m.insert("_BOOT_ID", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });
        m.insert("_MACHINE_ID", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });

        // Systemd specific
        m.insert("_SYSTEMD_UNIT", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: Some("service"),
        });
        m.insert("_SYSTEMD_SLICE", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });
        m.insert("_SYSTEMD_CGROUP", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });
        m.insert("_SYSTEMD_INVOCATION_ID", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });

        // Transport information
        m.insert("_TRANSPORT", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });

        // Syslog compatibility
        m.insert("SYSLOG_FACILITY", FieldInfo {
            field_type: FieldType::Integer,
            kind: Kind::integer(),
            meaning: None,
        });
        m.insert("SYSLOG_IDENTIFIER", FieldInfo {
            field_type: FieldType::Bytes,
            kind: Kind::bytes(),
            meaning: None,
        });
        m.insert("SYSLOG_PID", FieldInfo {
            field_type: FieldType::Integer,
            kind: Kind::integer(),
            meaning: None,
        });
        
        m
    })
}

/// Config used to build a `JournalExportDeserializer`.
#[configurable_component]
#[derive(Debug, Clone, Default)]
pub struct JournalExportDeserializerConfig {
    /// Journal Export-specific decoding options.
    #[serde(default, skip_serializing_if = "vector_core::serde::is_default")]
    pub journal_export: JournalExportDeserializerOptions,
}

impl JournalExportDeserializerConfig {
    /// Creates a new `JournalExportDeserializerConfig`.
    pub fn new(options: JournalExportDeserializerOptions) -> Self {
        Self {
            journal_export: options,
        }
    }

    /// Build the `JournalExportDeserializer` from this configuration.
    pub fn build(&self) -> JournalExportDeserializer {
        JournalExportDeserializer {
            lossy: self.journal_export.lossy,
            preserve_original_fields: self.journal_export.preserve_original_fields,
        }
    }

    /// Returns the input type for this deserializer.
    pub const fn input_type() -> DataType {
        DataType::Log
    }

    /// Returns the output type for this deserializer.
    pub fn output_type(&self) -> DataType {
        DataType::Log
    }

    fn add_common_journal_fields(
        definition: schema::Definition,
        log_namespace: LogNamespace,
    ) -> schema::Definition {
        let mut def = definition;
        for (&name, info) in field_definitions().iter() {
            let path = owned_value_path!(name);
            def = match log_namespace {
                LogNamespace::Legacy => def.optional_field(&path, info.kind.clone(), info.meaning),
                LogNamespace::Vector => def.with_metadata_field(&path, info.kind.clone(), info.meaning),
            };
        }
        def
    }

    /// Returns the schema definition for this deserializer.
    pub fn schema_definition(&self, log_namespace: LogNamespace) -> schema::Definition {
        match log_namespace {
            LogNamespace::Legacy => {
                let mut definition = schema::Definition::empty_legacy_namespace()
                    .with_event_field(
                        log_schema().message_key().expect("valid message key"),
                        Kind::bytes(),
                        Some("message"),
                    );

                if let Some(timestamp_key) = log_schema().timestamp_key() {
                    definition = definition.optional_field(
                        timestamp_key,
                        Kind::timestamp(),
                        Some("timestamp"),
                    )
                }

                Self::add_common_journal_fields(definition, log_namespace)
                    .unknown_fields(Kind::bytes())
            }
            LogNamespace::Vector => {
                Self::add_common_journal_fields(
                    schema::Definition::new_with_default_metadata(Kind::bytes(), [log_namespace])
                        .with_meaning(OwnedTargetPath::event_root(), "message"),
                    log_namespace,
                )
                .unknown_fields(Kind::bytes())
            }
        }
    }

    /// Returns the schema requirements for this deserializer.
    pub fn schema_requirement() -> schema::Requirement {
        schema::Requirement::empty()
    }
}

/// Journal Export-specific decoding options.
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct JournalExportDeserializerOptions {
    /// Determines whether or not to replace invalid UTF-8 sequences instead of failing.
    ///
    /// When true, invalid UTF-8 sequences are replaced with the [`U+FFFD REPLACEMENT CHARACTER`][U+FFFD].
    ///
    /// [U+FFFD]: https://en.wikipedia.org/wiki/Specials_(Unicode_block)#Replacement_character
    #[serde(
        default = "default_lossy",
        skip_serializing_if = "vector_core::serde::is_default"
    )]
    #[derivative(Default(value = "default_lossy()"))]
    pub lossy: bool,

    /// Determines whether to preserve the original field names when decoding in Vector namespace.
    ///
    /// When true, original field names (like `__REALTIME_TIMESTAMP`, `MESSAGE`) are preserved in the event metadata.
    /// When false, only the mapped field names (like `timestamp`, `message`) are kept.
    #[serde(default = "default_preserve_original_fields")]
    pub preserve_original_fields: bool,
}

fn default_preserve_original_fields() -> bool {
    false
}

impl JournalExportDeserializer {
    fn parse_field_value(&self, key: &str, value: &[u8]) -> vector_common::Result<Value> {
        let field_type = field_definitions()
            .get(key)
            .map(|info| info.field_type)
            .unwrap_or(FieldType::Bytes);

        match field_type {
            FieldType::Timestamp => {
                // Convert bytes to string first
                let str_value = if self.lossy {
                    String::from_utf8_lossy(value).into_owned()
                } else {
                    String::from_utf8(value.to_vec())
                        .map_err(|e| format!("Invalid UTF-8 in field '{}': {}", key, e))?
                };
                
                match str_value.parse::<i64>() {
                    Ok(micros) => {
                        let secs = micros / 1_000_000;
                        let nsecs = (micros % 1_000_000) * 1000;
                        if let Some(dt) = Utc.timestamp_opt(secs, nsecs as u32).earliest() {
                            Ok(Value::Timestamp(dt))
                        } else {
                            Err(format!("Invalid timestamp value for {}: {}", key, str_value).into())
                        }
                    }
                    Err(_) => Err(format!("Failed to parse timestamp for {}: {}", key, str_value).into()),
                }
            }
            FieldType::Integer => {
                // Convert bytes to string first
                let str_value = if self.lossy {
                    String::from_utf8_lossy(value).into_owned()
                } else {
                    String::from_utf8(value.to_vec())
                        .map_err(|e| format!("Invalid UTF-8 in field '{}': {}", key, e))?
                };
                
                match str_value.parse::<i64>() {
                    Ok(num) => Ok(Value::Integer(num)),
                    Err(_) => Err(format!("Failed to parse integer for {}: {}", key, str_value).into()),
                }
            }
            FieldType::Bytes => {
                if self.lossy {
                    Ok(Value::from(String::from_utf8_lossy(value).into_owned()))
                } else {
                    String::from_utf8(value.to_vec())
                        .map(Value::from)
                        .map_err(|e| format!("Invalid UTF-8 in field '{}': {}", key, e).into())
                }
            }
        }
    }

    fn decode_entry(&self, input: &[u8]) -> vector_common::Result<Option<LogEvent>> {
        let mut event = LogEvent::default();
        let mut has_fields = false;
        let mut lines = input.lines();

        while let Some(Ok(line)) = lines.next() {
            if line.is_empty() {
                // End of entry
                if has_fields {
                    return Ok(Some(event));
                }
                continue;
            }
            if let Some(equals_pos) = line.find('=') {
                // Format 1: KEY=value
                let (key, value) = line.split_at(equals_pos);
                if key.is_empty() {
                    return Err("Unexpected empty key in journal entry".into());
                }

                let data = &value[1..].as_bytes(); // Skip the '=' character
                let value = self.parse_field_value(key, data)?;
                
                // Handle field mapping based on preserve_original_fields
                if let Some(meaning) = field_definitions().get(key).and_then(|info| info.meaning) {
                    if self.preserve_original_fields {
                        event.insert(key, value.clone());
                    } 
                    event.insert(meaning, value);
                } else {
                    event.insert(key, value);
                }
                has_fields = true;
            } else {
                // Format 2: Binary data
                let key = line.as_str(); // First line is the key

                // We need to read the size from the next line
                if let Some(Ok(line)) = lines.next() {
                    let line_bytes = line.as_bytes();
                    
                    if line_bytes.len() < 8 {
                        return Err("Incomplete binary data: size line too short".into());
                    }

                    // Read the 8-byte little-endian size
                    let binary_data_size: [u8; 8] = line_bytes[..8].try_into()
                        .map_err(|_| "Failed to read binary size bytes")?;
                    let mut remaining_binary_size = u64::from_le_bytes(binary_data_size) as usize;

                    // Setup the data buffer
                    let mut data = Vec::with_capacity(remaining_binary_size);

                    if line_bytes.len() > 8 {
                        let bytes_to_take = (line_bytes.len() - 8).min(remaining_binary_size);
                        data.extend_from_slice(&line_bytes[8..8 + bytes_to_take]);
                        remaining_binary_size -= bytes_to_take;
                        if remaining_binary_size > 0 {
                            data.push(b'\n');
                            remaining_binary_size -= 1;
                        }
                    }

                    // Read the binary data across multiple lines
                    while remaining_binary_size > 0 {
                        if let Some(Ok(line)) = lines.next() {
                            let line_bytes = line.as_bytes();
                            let bytes_to_take = line_bytes.len().min(remaining_binary_size);
                            data.extend_from_slice(&line_bytes[..bytes_to_take]);
                            remaining_binary_size -= bytes_to_take;
                            if remaining_binary_size > 0 {
                                data.push(b'\n');
                                remaining_binary_size -= 1;
                            }
                        } else {
                            return Err("Unexpected end of binary data".into());
                        }
                    }

                    // Process the binary data
                    let value = self.parse_field_value(key, &data)?;
                    
                    // Handle field mapping based on preserve_original_fields
                    if let Some(meaning) = field_definitions().get(key).and_then(|info| info.meaning) {
                        if self.preserve_original_fields {
                            event.insert(key, value.clone());
                        } 
                        event.insert(meaning, value);
                    } else {
                        event.insert(key, value);
                    }
                    has_fields = true;
                } else {
                    return Err("Unexpected end of entry while reading binary data".into());
                }
            }
        }

        if has_fields {
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }
}

impl Deserializer for JournalExportDeserializer {
    fn parse(
        &self,
        bytes: Bytes,
        _log_namespace: LogNamespace,
    ) -> vector_common::Result<SmallVec<[Event; 1]>> {
        let mut events = SmallVec::new();
        let mut current_chunk = &bytes[..];
        
        while !current_chunk.is_empty() {
            // Find the double newline that separates entries
            let mut double_newline_pos = None;
            for i in 0..current_chunk.len() - 1 {
                if current_chunk[i] == b'\n' && current_chunk[i + 1] == b'\n' {
                    double_newline_pos = Some(i);
                    break;
                }
            }

            match double_newline_pos {
                Some(pos) => {
                    // Parse the current entry
                    if let Some(event) = self.decode_entry(&current_chunk[..pos])? {
                        events.push(Event::Log(event));
                    }
                    // Move past the double newline
                    current_chunk = &current_chunk[pos + 2..];
                }
                None => {
                    // Parse the final entry
                    if let Some(event) = self.decode_entry(current_chunk)? {
                        events.push(Event::Log(event));
                    }
                    break;
                }
            }
        }
        
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vector_core::config::LogNamespace;

    #[test]
    fn test_decode_single_entry() {
        let input = "__REALTIME_TIMESTAMP=1707116545123456\n\
                     MESSAGE=Hello 🦀 Rust\n\
                     _PID=123\n\
                     PRIORITY=7\n\
                     _HOSTNAME=test.host.com\n\
                     _SYSTEMD_UNIT=test.service\n\
                     CUSTOM_FIELD=value\n\n".as_bytes();
        
        // Test Legacy namespace
        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        let events = deserializer.parse(Bytes::from_static(input), LogNamespace::Legacy).unwrap();
        
        assert_eq!(events.len(), 1);
        let event = events[0].as_log();
        
        // Check timestamp, integer and string fields in Legacy namespace
        assert_eq!(event["__REALTIME_TIMESTAMP"].as_timestamp().unwrap().timestamp(), 1707116545);
        assert_eq!(event["_PID"].as_integer().unwrap(), 123);
        assert_eq!(event["MESSAGE"], "Hello 🦀 Rust".into());
        assert_eq!(event["_HOSTNAME"], "test.host.com".into());
        assert_eq!(event["_SYSTEMD_UNIT"], "test.service".into());
        assert_eq!(event["CUSTOM_FIELD"], "value".into());

        // Test Vector namespace with preserved fields
        let events = deserializer.parse(Bytes::from_static(input), LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);
        let event = events[0].as_log();

        // Check fields are mapped correctly in Vector namespace
        assert_eq!(event["timestamp"].as_timestamp().unwrap().timestamp(), 1707116545);
        assert_eq!(event["message"], "Hello 🦀 Rust".into());
        assert_eq!(event["host"], "test.host.com".into());
        assert_eq!(event["service"], "test.service".into());

        // Original fields should be present in metadata
        assert_eq!(event["__REALTIME_TIMESTAMP"].as_timestamp().unwrap().timestamp(), 1707116545);
        assert_eq!(event["MESSAGE"], "Hello 🦀 Rust".into());
        assert_eq!(event["_HOSTNAME"], "test.host.com".into());
        assert_eq!(event["_SYSTEMD_UNIT"], "test.service".into());

        // Test Vector namespace without preserved fields
        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: false,
        };
        let events = deserializer.parse(Bytes::from_static(input), LogNamespace::Vector).unwrap();
        assert_eq!(events.len(), 1);
        let event = events[0].as_log();

        // Check only mapped fields are present
        assert_eq!(event["timestamp"].as_timestamp().unwrap().timestamp(), 1707116545);
        assert_eq!(event["message"], "Hello 🦀 Rust".into());
        assert_eq!(event["host"], "test.host.com".into());
        assert_eq!(event["service"], "test.service".into());

        // Original fields should not be present
        assert!(event.get("__REALTIME_TIMESTAMP").is_none());
        assert!(event.get("MESSAGE").is_none());
        assert!(event.get("_HOSTNAME").is_none());
        assert!(event.get("_SYSTEMD_UNIT").is_none());
    }

    #[test]
    fn test_decode_multiple_entries() {
        let input = b"MESSAGE=first message\nPRIORITY=6\n\n\
                     MESSAGE=second message\nPRIORITY=4\n\n";
        
        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        let events = deserializer.parse(Bytes::from_static(input), LogNamespace::Legacy).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].as_log()["MESSAGE"], "first message".into());
        assert_eq!(events[0].as_log()["PRIORITY"], Value::Integer(6));
        assert_eq!(events[1].as_log()["MESSAGE"], "second message".into());
        assert_eq!(events[1].as_log()["PRIORITY"], Value::Integer(4));
    }

    #[test]
    fn test_decode_binary_message() {
        let input = b"MESSAGE\n\x07\x00\x00\x00\x00\x00\x00\x00foo\nbar\nPRIORITY=6\n\n";
        
        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        let events = deserializer.parse(Bytes::from_static(input), LogNamespace::Legacy).unwrap();
        
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log()["MESSAGE"], "foo\nbar".into());
        assert_eq!(events[0].as_log()["PRIORITY"], Value::Integer(6));
    }

    #[test]
    fn test_field_type_parsing_errors() {
        let test_cases = [
            (b"_PID=not_a_number\n\n".as_ref(), "Failed to parse integer for _PID: not_a_number"),
            (b"__REALTIME_TIMESTAMP=invalid\n\n".as_ref(), "Failed to parse timestamp for __REALTIME_TIMESTAMP: invalid"),
            (b"__REALTIME_TIMESTAMP=9223372036854775808\n\n".as_ref(), "Failed to parse timestamp for __REALTIME_TIMESTAMP"),
        ];

        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        for (input, expected_err) in test_cases {
            let result = deserializer.parse(Bytes::from_static(input), LogNamespace::Legacy);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains(expected_err));
        }
    }

    #[test]
    fn test_malformed_entries() {
        let test_cases = [
            (b"=no_key\n\n".as_ref(), "Unexpected empty key"),
            (b"MESSAGE\n\x08\x00\x00\x00\x00\x00\x00\x00foo\n\n".as_ref(), "Unexpected end of binary data"),
            (b"MESSAGE\ninvalid\n\n".as_ref(), "Incomplete binary data: size line too short"),
        ];

        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        for (input, expected_err) in test_cases {
            let result = deserializer.parse(Bytes::from_static(input), LogNamespace::Legacy);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains(expected_err));
        };
    }

    #[test]
    fn test_binary_data_with_newlines() {
        let mut input = Vec::new();
        input.extend_from_slice(b"MESSAGE\n");
        input.extend_from_slice(&11u64.to_le_bytes());
        input.extend_from_slice(b"foo\n");  // First line of binary data
        input.extend_from_slice(b"bar\n");  // Second line
        input.extend_from_slice(b"baz\n");  // Third line
        input.extend_from_slice(b"\n");     // Entry separator

        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        let events = deserializer.parse(Bytes::from(input), LogNamespace::Legacy).unwrap();
        
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log()["MESSAGE"], "foo\nbar\nbaz".into());
    }

    #[test]
    fn test_binary_data_with_size_and_data_on_same_line() {
        // Test when size and some data are on the same line
        let mut input = Vec::new();
        input.extend_from_slice(b"MESSAGE\n");
        input.extend_from_slice(&7u64.to_le_bytes());  // size of "foo\nbar"
        input.extend_from_slice(b"foo\n");  // First part on same line as size
        input.extend_from_slice(b"bar\n");  // Rest of the data
        input.extend_from_slice(b"\n");     // Entry separator

        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        let events = deserializer.parse(Bytes::from(input), LogNamespace::Legacy).unwrap();
        
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].as_log()["MESSAGE"], "foo\nbar".into());
    }

    #[test]
    fn test_mixed_binary_and_regular_fields() {
        let mut input = Vec::new();
        // Regular field
        input.extend_from_slice(b"PRIORITY=6\n");
        // Binary field
        input.extend_from_slice(b"MESSAGE\n");
        input.extend_from_slice(&7u64.to_le_bytes());
        input.extend_from_slice(b"foo\nbar\n");
        // Another regular field
        input.extend_from_slice(b"_PID=1234\n");
        input.extend_from_slice(b"\n");  // Entry separator

        let deserializer = JournalExportDeserializer { 
            lossy: false,
            preserve_original_fields: true,
        };
        let events = deserializer.parse(Bytes::from(input), LogNamespace::Legacy).unwrap();
        
        assert_eq!(events.len(), 1);
        let event = events[0].as_log();
        assert_eq!(event["MESSAGE"], "foo\nbar".into());
        assert_eq!(event["PRIORITY"], Value::Integer(6));
        assert_eq!(event["_PID"], Value::Integer(1234));
    }
    // TODO: Add tests for lossy mode
} 