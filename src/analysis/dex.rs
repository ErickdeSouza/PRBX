use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};

const HEADER_SIZE: usize = 0x70;
const ACC_NATIVE: u32 = 0x0100;
const MAX_TABLE_ITEMS: usize = 2_000_000;

pub struct DexReport {
    pub native_methods: Vec<NativeMethod>,
    pub framework_calls: BTreeMap<String, usize>,
    pub framework_call_sites: usize,
    pub library_loads: Vec<LibraryLoad>,
    pub framework_classes: BTreeSet<String>,
}

pub struct NativeMethod {
    pub class_name: String,
    pub method_name: String,
    pub parameter_descriptor: String,
    pub dex_file: String,
}

pub struct LibraryLoad {
    pub caller: String,
    pub target: String,
    pub string_constants: Vec<String>,
    pub dex_file: String,
}

struct MethodReference {
    class_name: String,
    method_name: String,
    parameter_descriptor: String,
}

pub fn parse(bytes: &[u8], dex_file: &str) -> Result<DexReport> {
    if bytes.len() < HEADER_SIZE || !bytes.starts_with(b"dex\n") {
        bail!("magic/header DEX inválido ou truncado");
    }
    let declared_size = read_u32(bytes, 32)? as usize;
    let header_size = read_u32(bytes, 36)? as usize;
    if header_size < HEADER_SIZE || declared_size > bytes.len() || declared_size < HEADER_SIZE {
        bail!("tamanho de cabeçalho/arquivo DEX inválido");
    }
    let bytes = &bytes[..declared_size];

    let strings = read_strings(bytes, read_u32(bytes, 56)?, read_u32(bytes, 60)?)?;
    let types = read_types(bytes, read_u32(bytes, 64)?, read_u32(bytes, 68)?, &strings)?;
    let prototypes = read_prototypes(bytes, read_u32(bytes, 72)?, read_u32(bytes, 76)?, &types)?;
    let methods = read_methods(
        bytes,
        read_u32(bytes, 88)?,
        read_u32(bytes, 92)?,
        &types,
        &strings,
        &prototypes,
    )?;
    let class_defs_size = read_u32(bytes, 96)? as usize;
    let class_defs_offset = read_u32(bytes, 100)? as usize;
    check_table_count(class_defs_size)?;
    checked_range(bytes, class_defs_offset, class_defs_size, 32)?;

    let mut native_methods = Vec::new();
    let mut framework_calls = BTreeMap::new();
    let mut framework_call_sites = 0;
    let mut framework_classes = BTreeSet::new();
    let mut pending_loads = Vec::new();
    for index in 0..class_defs_size {
        let class_offset = class_defs_offset + index * 32;
        let class_idx = read_u32(bytes, class_offset)? as usize;
        let class_data_offset = read_u32(bytes, class_offset + 24)? as usize;
        if class_data_offset == 0 {
            continue;
        }
        let class_name = types
            .get(class_idx)
            .context("índice de classe DEX inválido")?;
        let mut cursor = class_data_offset;
        let static_fields = read_uleb128(bytes, &mut cursor)?;
        let instance_fields = read_uleb128(bytes, &mut cursor)?;
        let direct_methods = read_uleb128(bytes, &mut cursor)?;
        let virtual_methods = read_uleb128(bytes, &mut cursor)?;

        skip_encoded_fields(bytes, &mut cursor, static_fields)?;
        skip_encoded_fields(bytes, &mut cursor, instance_fields)?;
        for method_count in [direct_methods, virtual_methods] {
            let mut method_index = 0u32;
            for _ in 0..method_count {
                method_index = method_index
                    .checked_add(read_uleb128(bytes, &mut cursor)?)
                    .context("índice de método DEX excedeu limites")?;
                let access_flags = read_uleb128(bytes, &mut cursor)?;
                let code_offset = read_uleb128(bytes, &mut cursor)? as usize;
                let method = methods
                    .get(method_index as usize)
                    .context("índice de método DEX inválido")?;
                let caller = format!(
                    "{}->{}{}",
                    class_name, method.method_name, method.parameter_descriptor
                );

                if access_flags & ACC_NATIVE != 0 {
                    native_methods.push(NativeMethod {
                        class_name: class_name
                            .replace('/', ".")
                            .trim_start_matches('L')
                            .trim_end_matches(';')
                            .to_owned(),
                        method_name: method.method_name.clone(),
                        parameter_descriptor: method.parameter_descriptor.clone(),
                        dex_file: dex_file.to_owned(),
                    });
                }
                if code_offset != 0 {
                    let code = scan_code(bytes, code_offset, &methods, &strings)?;
                    for target in code.method_calls {
                        if is_framework_class(&target.class_name) {
                            framework_call_sites += 1;
                            *framework_calls
                                .entry(format!("{}->{}", target.class_name, target.method_name))
                                .or_insert(0) += 1;
                            framework_classes.insert(target.class_name.clone());
                        }
                        if is_library_load(&target) {
                            pending_loads.push(LibraryLoad {
                                caller: caller.clone(),
                                target: format!("{}->{}", target.class_name, target.method_name),
                                string_constants: code.string_constants.clone(),
                                dex_file: dex_file.to_owned(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(DexReport {
        native_methods,
        framework_calls,
        framework_call_sites,
        library_loads: pending_loads,
        framework_classes,
    })
}

struct CodeScan {
    method_calls: Vec<MethodReference>,
    string_constants: Vec<String>,
}

fn scan_code(
    bytes: &[u8],
    code_offset: usize,
    methods: &[MethodReference],
    strings: &[String],
) -> Result<CodeScan> {
    let instruction_count = read_u32(bytes, code_offset + 12)? as usize;
    let instruction_start = code_offset
        .checked_add(16)
        .context("offset do bytecode DEX excedeu limites")?;
    checked_range(bytes, instruction_start, instruction_count, 2)?;
    let units = (0..instruction_count)
        .map(|index| read_u16(bytes, instruction_start + index * 2))
        .collect::<Result<Vec<_>>>()?;

    let mut method_calls = Vec::new();
    let mut string_constants = Vec::new();
    let mut cursor = 0;
    while cursor < units.len() {
        let opcode = (units[cursor] & 0xff) as u8;
        let instruction_size = instruction_size(&units, cursor)?;
        if instruction_size == 0 || cursor + instruction_size > units.len() {
            bail!("instrução DEX truncada no offset {cursor}");
        }
        if (0x6e..=0x72).contains(&opcode) || (0x74..=0x78).contains(&opcode) {
            let method_index = *units
                .get(cursor + 1)
                .context("invoke DEX sem índice de método")?
                as usize;
            let method = methods
                .get(method_index)
                .context("invoke DEX referencia método inexistente")?;
            method_calls.push(MethodReference {
                class_name: method.class_name.clone(),
                method_name: method.method_name.clone(),
                parameter_descriptor: method.parameter_descriptor.clone(),
            });
        } else if opcode == 0xfa || opcode == 0xfb {
            let method_index = *units
                .get(cursor + 1)
                .context("invoke-polymorphic DEX sem índice de método")?
                as usize;
            let method = methods
                .get(method_index)
                .context("invoke-polymorphic DEX referencia método inexistente")?;
            method_calls.push(MethodReference {
                class_name: method.class_name.clone(),
                method_name: method.method_name.clone(),
                parameter_descriptor: method.parameter_descriptor.clone(),
            });
        } else if opcode == 0x1a || opcode == 0x1b {
            let string_index = if opcode == 0x1a {
                *units.get(cursor + 1).context("const-string DEX truncado")? as u32
            } else {
                let low = *units
                    .get(cursor + 1)
                    .context("const-string/jumbo DEX truncado")?;
                let high = *units
                    .get(cursor + 2)
                    .context("const-string/jumbo DEX truncado")?;
                u32::from(low) | (u32::from(high) << 16)
            };
            let value = strings
                .get(string_index as usize)
                .context("const-string DEX referencia string inexistente")?;
            string_constants.push(value.clone());
        }
        cursor += instruction_size;
    }

    Ok(CodeScan {
        method_calls,
        string_constants,
    })
}

fn instruction_size(units: &[u16], cursor: usize) -> Result<usize> {
    let instruction = *units.get(cursor).context("opcode DEX ausente")?;
    let opcode = (instruction & 0xff) as u8;

    if opcode == 0x00 {
        return match instruction >> 8 {
            0x00 => Ok(1),
            0x01 => {
                let size = *units
                    .get(cursor + 1)
                    .context("packed-switch payload truncado")? as usize;
                Ok(4usize.saturating_add(size.saturating_mul(2)))
            }
            0x02 => {
                let size = *units
                    .get(cursor + 1)
                    .context("sparse-switch payload truncado")? as usize;
                Ok(2usize.saturating_add(size.saturating_mul(4)))
            }
            0x03 => {
                let element_width =
                    *units.get(cursor + 1).context("array payload truncado")? as usize;
                let low = *units.get(cursor + 2).context("array payload truncado")? as usize;
                let high = *units.get(cursor + 3).context("array payload truncado")? as usize;
                let size = low | (high << 16);
                Ok(4usize.saturating_add(element_width.saturating_mul(size).saturating_add(1) / 2))
            }
            _ => bail!("identificador de payload DEX desconhecido"),
        };
    }

    let size = match opcode {
        0x01
        | 0x04
        | 0x07
        | 0x0a..=0x12
        | 0x1d..=0x1e
        | 0x21
        | 0x27..=0x28
        | 0x7b..=0x8f
        | 0xb0..=0xcf => 1,
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15..=0x16
        | 0x19..=0x1a
        | 0x1c
        | 0x1f..=0x20
        | 0x22..=0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe2
        | 0xfe..=0xff => 2,
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24..=0x26
        | 0x2a..=0x2c
        | 0x6e..=0x72
        | 0x74..=0x78
        | 0xfc..=0xfd => 3,
        0x18 => 5,
        0xfa..=0xfb => 4,
        _ => bail!("opcode DEX não reconhecido: 0x{opcode:02x}"),
    };
    Ok(size)
}

fn is_framework_class(class_name: &str) -> bool {
    class_name.starts_with("Landroid/")
        || class_name.starts_with("Ljava/")
        || class_name.starts_with("Ljavax/")
        || class_name.starts_with("Ldalvik/")
}

fn is_library_load(method: &MethodReference) -> bool {
    (method.class_name == "Ljava/lang/System;"
        && (method.method_name == "loadLibrary" || method.method_name == "load"))
        || (method.class_name == "Ljava/lang/Runtime;" && method.method_name == "load")
}

fn read_strings(bytes: &[u8], count: u32, offset: u32) -> Result<Vec<String>> {
    let count = count as usize;
    check_table_count(count)?;
    let offset = offset as usize;
    checked_range(bytes, offset, count, 4)?;
    let mut strings = Vec::with_capacity(count);
    for index in 0..count {
        let string_offset = read_u32(bytes, offset + index * 4)? as usize;
        let mut cursor = string_offset;
        let _utf16_length = read_uleb128(bytes, &mut cursor)?;
        let end = bytes
            .get(cursor..)
            .context("string data DEX fora dos limites")?
            .iter()
            .position(|byte| *byte == 0)
            .map(|length| cursor + length)
            .context("string DEX sem terminador")?;
        let value = String::from_utf8_lossy(&bytes[cursor..end]).into_owned();
        strings.push(value);
    }
    Ok(strings)
}

fn read_types(bytes: &[u8], count: u32, offset: u32, strings: &[String]) -> Result<Vec<String>> {
    let count = count as usize;
    check_table_count(count)?;
    let offset = offset as usize;
    checked_range(bytes, offset, count, 4)?;
    let mut types = Vec::with_capacity(count);
    for index in 0..count {
        let descriptor_index = read_u32(bytes, offset + index * 4)? as usize;
        types.push(
            strings
                .get(descriptor_index)
                .context("índice de string de tipo DEX inválido")?
                .clone(),
        );
    }
    Ok(types)
}

fn read_methods(
    bytes: &[u8],
    count: u32,
    offset: u32,
    types: &[String],
    strings: &[String],
    prototypes: &[String],
) -> Result<Vec<MethodReference>> {
    let count = count as usize;
    check_table_count(count)?;
    let offset = offset as usize;
    checked_range(bytes, offset, count, 8)?;
    let mut methods = Vec::with_capacity(count);
    for index in 0..count {
        let method_offset = offset + index * 8;
        let class_index = read_u16(bytes, method_offset)? as usize;
        let proto_index = read_u16(bytes, method_offset + 2)? as usize;
        let name_index = read_u32(bytes, method_offset + 4)? as usize;
        let class_name = types
            .get(class_index)
            .context("classe de método DEX inválida")?;
        let method_name = strings
            .get(name_index)
            .context("nome de método DEX inválido")?;
        let prototype = prototypes
            .get(proto_index)
            .context("índice de protótipo de método DEX inválido")?;
        let parameter_descriptor = prototype
            .split_once(')')
            .context("descritor de protótipo DEX inválido")?
            .0
            .to_owned()
            + ")";
        methods.push(MethodReference {
            class_name: class_name.clone(),
            method_name: method_name.clone(),
            parameter_descriptor,
        });
    }
    Ok(methods)
}

fn read_prototypes(bytes: &[u8], count: u32, offset: u32, types: &[String]) -> Result<Vec<String>> {
    let count = count as usize;
    check_table_count(count)?;
    let offset = offset as usize;
    checked_range(bytes, offset, count, 12)?;
    let mut prototypes = Vec::with_capacity(count);
    for index in 0..count {
        let prototype_offset = offset + index * 12;
        let return_type_index = read_u32(bytes, prototype_offset + 4)? as usize;
        let parameters_offset = read_u32(bytes, prototype_offset + 8)? as usize;
        let return_type = types
            .get(return_type_index)
            .context("índice de tipo de retorno DEX inválido")?;
        let mut descriptor = String::from("(");
        if parameters_offset != 0 {
            let size = read_u32(bytes, parameters_offset)? as usize;
            check_table_count(size)?;
            checked_range(bytes, parameters_offset + 4, size, 2)?;
            for parameter in 0..size {
                let type_index = read_u16(bytes, parameters_offset + 4 + parameter * 2)? as usize;
                descriptor.push_str(
                    types
                        .get(type_index)
                        .context("índice de tipo de parâmetro DEX inválido")?,
                );
            }
        }
        descriptor.push(')');
        descriptor.push_str(return_type);
        prototypes.push(descriptor);
    }
    Ok(prototypes)
}

fn skip_encoded_fields(bytes: &[u8], cursor: &mut usize, count: u32) -> Result<()> {
    for _ in 0..count {
        let _field_index_diff = read_uleb128(bytes, cursor)?;
        let _access_flags = read_uleb128(bytes, cursor)?;
    }
    Ok(())
}

fn read_uleb128(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*cursor).context("ULEB128 DEX truncado")?;
        *cursor += 1;
        if shift == 28 && byte & 0xf0 != 0 {
            bail!("ULEB128 DEX excedeu 32 bits");
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("ULEB128 DEX inválido")
}

fn checked_range(bytes: &[u8], offset: usize, count: usize, item_size: usize) -> Result<()> {
    let length = count
        .checked_mul(item_size)
        .context("tamanho de tabela DEX excedeu limites")?;
    let end = offset
        .checked_add(length)
        .context("offset de tabela DEX excedeu limites")?;
    if end > bytes.len() {
        bail!("tabela DEX truncada");
    }
    Ok(())
}

fn check_table_count(count: usize) -> Result<()> {
    if count > MAX_TABLE_ITEMS {
        bail!("tabela DEX excede o limite de {MAX_TABLE_ITEMS} itens");
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let slice = bytes
        .get(offset..offset + 2)
        .context("arquivo DEX truncado")?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let slice = bytes
        .get(offset..offset + 4)
        .context("arquivo DEX truncado")?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_dex_input() {
        assert!(parse(b"not a dex file", "classes.dex").is_err());
    }

    #[test]
    fn reads_uleb128_and_rejects_truncation() {
        let mut offset = 0;
        assert_eq!(
            read_uleb128(&[0xe5, 0x8e, 0x26], &mut offset).unwrap(),
            624485
        );
        let mut offset = 0;
        assert!(read_uleb128(&[0x80], &mut offset).is_err());
    }

    #[test]
    fn recognizes_standard_dex_instruction_sizes() {
        let units = [
            0x0012, 0x0013, 0x0014, 0x006e, 0x00fa, 0x0000, 0x0100, 0x0001, 0, 0, 0, 0,
        ];
        assert_eq!(instruction_size(&units, 0).unwrap(), 1);
        assert_eq!(instruction_size(&units, 1).unwrap(), 2);
        assert_eq!(instruction_size(&units, 2).unwrap(), 3);
        assert_eq!(instruction_size(&units, 3).unwrap(), 3);
        assert_eq!(instruction_size(&units, 4).unwrap(), 4);
        assert_eq!(instruction_size(&units, 5).unwrap(), 1);
        assert_eq!(instruction_size(&units, 6).unwrap(), 6);
    }

    #[test]
    fn reads_parameter_and_return_types_from_dex_prototypes() {
        let mut bytes = [0_u8; 20];
        bytes[4..8].copy_from_slice(&2_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&12_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..18].copy_from_slice(&0_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&1_u16.to_le_bytes());

        let prototypes = read_prototypes(
            &bytes,
            1,
            0,
            &[
                "I".to_owned(),
                "Ljava/lang/String;".to_owned(),
                "V".to_owned(),
            ],
        )
        .unwrap();
        assert_eq!(prototypes, ["(ILjava/lang/String;)V"]);
    }
}
