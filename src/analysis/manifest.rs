use anyhow::{Context, Result, bail};

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const UTF8_FLAG: u32 = 0x0000_0100;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const ANDROID_NAMESPACE: &str = "http://schemas.android.com/apk/res/android";
const MAX_STRING_COUNT: usize = 500_000;

#[derive(Default)]
pub struct ManifestReport {
    pub package: Option<String>,
    pub application_class: Option<String>,
    pub launcher_activity: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub components: Vec<Component>,
    pub permissions: Vec<String>,
    pub features: Vec<String>,
    pub native_libraries: Vec<String>,
    pub metadata: Vec<(String, String)>,
}

pub struct Component {
    pub kind: String,
    pub name: String,
}

struct Attribute {
    namespace: Option<String>,
    name: String,
    value: String,
}

pub fn parse(bytes: &[u8]) -> Result<ManifestReport> {
    if read_u16(bytes, 0)? != RES_XML_TYPE {
        bail!("tipo de documento XML binário inválido");
    }
    let declared_size = read_u32(bytes, 4)? as usize;
    if declared_size > bytes.len() || declared_size < 8 {
        bail!("tamanho do documento XML binário inválido");
    }

    let mut report = ManifestReport::default();
    let mut strings = Vec::new();
    let mut cursor = read_u16(bytes, 2)? as usize;
    let mut current_component: Option<(String, String)> = None;
    let mut current_filter: Option<(bool, bool)> = None;

    while cursor < declared_size {
        let chunk_type = read_u16(bytes, cursor)?;
        let header_size = read_u16(bytes, cursor + 2)? as usize;
        let chunk_size = read_u32(bytes, cursor + 4)? as usize;
        if header_size < 8 || chunk_size < header_size || cursor + chunk_size > declared_size {
            bail!("chunk XML inválido no offset {cursor}");
        }

        match chunk_type {
            RES_STRING_POOL_TYPE => strings = parse_string_pool(bytes, cursor, chunk_size)?,
            RES_XML_START_ELEMENT_TYPE => {
                let (tag, attributes) = parse_start_element(bytes, cursor, chunk_size, &strings)?;
                process_start_tag(
                    &mut report,
                    &tag,
                    &attributes,
                    &mut current_component,
                    &mut current_filter,
                );
            }
            RES_XML_END_ELEMENT_TYPE => {
                let tag_name_index = read_u32(bytes, cursor + 20)?;
                let tag_name = string_at(&strings, tag_name_index)?;
                match tag_name {
                    "intent-filter" => {
                        if let (Some((kind, name)), Some((has_main, has_launcher))) =
                            (&current_component, current_filter.take())
                        {
                            if has_main
                                && has_launcher
                                && (kind == "activity" || kind == "activity-alias")
                            {
                                report.launcher_activity = Some(name.clone());
                            }
                        }
                    }
                    "activity" | "activity-alias" | "service" | "receiver" | "provider" => {
                        if current_component
                            .as_ref()
                            .is_some_and(|(kind, _)| kind == tag_name)
                        {
                            if let Some((kind, name)) = current_component.take() {
                                report.components.push(Component { kind, name });
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        cursor += chunk_size;
    }

    Ok(report)
}

fn process_start_tag(
    report: &mut ManifestReport,
    tag: &str,
    attributes: &[Attribute],
    current_component: &mut Option<(String, String)>,
    current_filter: &mut Option<(bool, bool)>,
) {
    let value = |name: &str| {
        attributes
            .iter()
            .find(|attribute| attribute.name == name)
            .map(|attribute| attribute.value.as_str())
    };
    let android_value = |name: &str| {
        attributes
            .iter()
            .find(|attribute| {
                attribute.name == name && attribute.namespace.as_deref() == Some(ANDROID_NAMESPACE)
            })
            .map(|attribute| attribute.value.as_str())
    };

    match tag {
        "manifest" => report.package = value("package").map(str::to_owned),
        "uses-sdk" => {
            report.min_sdk = android_value("minSdkVersion").map(str::to_owned);
            report.target_sdk = android_value("targetSdkVersion").map(str::to_owned);
        }
        tag if tag.starts_with("uses-permission") => {
            if let Some(permission) = android_value("name") {
                report.permissions.push(permission.to_owned());
            }
        }
        "uses-feature" => {
            if let Some(feature) = android_value("name") {
                report.features.push(feature.to_owned());
            }
        }
        "uses-native-library" => {
            if let Some(library) = android_value("name") {
                report.native_libraries.push(library.to_owned());
            }
        }
        "meta-data" => {
            if let Some(name) = android_value("name") {
                let value = android_value("value")
                    .or_else(|| android_value("resource"))
                    .unwrap_or("(sem valor resolvido)");
                report.metadata.push((name.to_owned(), value.to_owned()));
            }
        }
        "application" => {
            report.application_class = android_value("name").map(str::to_owned);
        }
        "activity" | "activity-alias" | "service" | "receiver" | "provider" => {
            if let Some(name) = android_value("name") {
                *current_component = Some((tag.to_owned(), name.to_owned()));
            }
        }
        "intent-filter" => *current_filter = Some((false, false)),
        "action" => {
            if android_value("name") == Some("android.intent.action.MAIN")
                && let Some((has_main, _)) = current_filter
            {
                *has_main = true;
            }
        }
        "category" => {
            if android_value("name") == Some("android.intent.category.LAUNCHER")
                && let Some((_, has_launcher)) = current_filter
            {
                *has_launcher = true;
            }
        }
        _ => {}
    }
}

fn parse_start_element(
    bytes: &[u8],
    offset: usize,
    chunk_size: usize,
    strings: &[String],
) -> Result<(String, Vec<Attribute>)> {
    let tag_name_index = read_u32(bytes, offset + 20)?;
    let tag_name = string_at(strings, tag_name_index)?.to_owned();
    let attribute_start = read_u16(bytes, offset + 24)? as usize;
    let attribute_size = read_u16(bytes, offset + 26)? as usize;
    let attribute_count = read_u16(bytes, offset + 28)? as usize;
    if attribute_size < 20 {
        bail!("tamanho de atributo XML inválido");
    }
    let attributes_offset = offset + 16 + attribute_start;
    let chunk_end = offset + chunk_size;
    let mut attributes = Vec::with_capacity(attribute_count);

    for index in 0..attribute_count {
        let attribute_offset = attributes_offset
            .checked_add(
                index
                    .checked_mul(attribute_size)
                    .context("overflow no atributo")?,
            )
            .context("overflow no atributo")?;
        if attribute_offset + 20 > chunk_end {
            bail!("atributo XML fora dos limites do chunk");
        }
        let namespace_index = read_u32(bytes, attribute_offset)?;
        let name_index = read_u32(bytes, attribute_offset + 4)?;
        let raw_value_index = read_u32(bytes, attribute_offset + 8)?;
        let data_type = *bytes
            .get(attribute_offset + 15)
            .context("tipo de valor XML ausente")?;
        let data = read_u32(bytes, attribute_offset + 16)?;
        let name = string_at(strings, name_index)?.to_owned();
        let value = if raw_value_index != u32::MAX {
            string_at(strings, raw_value_index)?.to_owned()
        } else if data_type == TYPE_STRING {
            string_at(strings, data)?.to_owned()
        } else if data_type == TYPE_INT_DEC {
            data.to_string()
        } else if data_type == TYPE_INT_HEX {
            format!("0x{data:x}")
        } else {
            format!("@0x{data:08x}")
        };
        let namespace = if namespace_index == u32::MAX {
            None
        } else {
            Some(string_at(strings, namespace_index)?.to_owned())
        };
        attributes.push(Attribute {
            namespace,
            name,
            value,
        });
    }

    Ok((tag_name, attributes))
}

fn parse_string_pool(bytes: &[u8], offset: usize, chunk_size: usize) -> Result<Vec<String>> {
    if chunk_size < 28 {
        bail!("string pool XML truncado");
    }
    let string_count = read_u32(bytes, offset + 8)? as usize;
    if string_count > MAX_STRING_COUNT {
        bail!("string pool excede o limite de {MAX_STRING_COUNT} strings");
    }
    let flags = read_u32(bytes, offset + 16)?;
    let strings_start = read_u32(bytes, offset + 20)? as usize;
    let offsets_start = offset + 28;
    if offsets_start + string_count.saturating_mul(4) > offset + chunk_size {
        bail!("índice de string pool fora dos limites");
    }

    let mut strings = Vec::with_capacity(string_count);
    for index in 0..string_count {
        let relative_offset = read_u32(bytes, offsets_start + index * 4)? as usize;
        let start = offset
            .checked_add(strings_start)
            .and_then(|base| base.checked_add(relative_offset))
            .context("offset de string pool inválido")?;
        let value = if flags & UTF8_FLAG != 0 {
            decode_utf8_string(bytes, start)?
        } else {
            decode_utf16_string(bytes, start)?
        };
        strings.push(value);
    }
    Ok(strings)
}

fn decode_utf8_string(bytes: &[u8], mut offset: usize) -> Result<String> {
    let (_, next) = read_length8(bytes, offset)?;
    offset = next;
    let (byte_length, next) = read_length8(bytes, offset)?;
    offset = next;
    let end = offset
        .checked_add(byte_length)
        .context("tamanho de string UTF-8 inválido")?;
    let slice = bytes.get(offset..end).context("string UTF-8 truncada")?;
    String::from_utf8(slice.to_vec()).context("string pool contém UTF-8 inválido")
}

fn decode_utf16_string(bytes: &[u8], mut offset: usize) -> Result<String> {
    let (unit_length, next) = read_length16(bytes, offset)?;
    offset = next;
    let byte_length = unit_length
        .checked_mul(2)
        .context("tamanho de string UTF-16 inválido")?;
    let slice = bytes
        .get(offset..offset + byte_length)
        .context("string UTF-16 truncada")?;
    let units = slice
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    Ok(char::decode_utf16(units)
        .map(|character| character.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect())
}

fn read_length8(bytes: &[u8], offset: usize) -> Result<(usize, usize)> {
    let first = *bytes.get(offset).context("comprimento UTF-8 truncado")?;
    if first & 0x80 == 0 {
        Ok((first as usize, offset + 1))
    } else {
        let second = *bytes
            .get(offset + 1)
            .context("comprimento UTF-8 truncado")?;
        Ok((((first & 0x7f) as usize) << 8 | second as usize, offset + 2))
    }
}

fn read_length16(bytes: &[u8], offset: usize) -> Result<(usize, usize)> {
    let first = read_u16(bytes, offset)?;
    if first & 0x8000 == 0 {
        Ok((first as usize, offset + 2))
    } else {
        let second = read_u16(bytes, offset + 2)?;
        Ok((
            ((first & 0x7fff) as usize) << 16 | second as usize,
            offset + 4,
        ))
    }
}

fn string_at(strings: &[String], index: u32) -> Result<&str> {
    strings
        .get(index as usize)
        .map(String::as_str)
        .context("índice de string XML inválido")
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .context("arquivo XML truncado")?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .context("arquivo XML truncado")?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_variable_length_utf8_string_sizes() {
        assert_eq!(read_length8(&[0x7f], 0).unwrap(), (127, 1));
        assert_eq!(read_length8(&[0x81, 0x00], 0).unwrap(), (256, 2));
        assert!(read_length8(&[0x80], 0).is_err());
    }

    #[test]
    fn rejects_non_binary_xml() {
        assert!(parse(b"<manifest/>").is_err());
    }
}
