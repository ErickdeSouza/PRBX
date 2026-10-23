use anyhow::{Context, Result};
use goblin::elf::{Elf, header, program_header, reloc};
use std::collections::BTreeMap;

const ELF_PAGE_SIZE: u64 = 4096;

#[derive(Clone, Debug)]
pub struct ElfLoadSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
    pub mapped_start: u64,
    pub mapped_end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Debug)]
pub struct ElfLoadPlan {
    pub page_size: u64,
    pub image_start: u64,
    pub image_end: u64,
    pub image_size: u64,
    pub segments: Vec<ElfLoadSegment>,
}

#[derive(Clone, Debug)]
pub struct ElfRelocation {
    pub offset: u64,
    pub addend: Option<i64>,
    pub relocation_type: u32,
    pub relocation_name: String,
    pub symbol_index: usize,
    pub symbol_name: Option<String>,
}

pub struct ElfReport {
    pub class: &'static str,
    pub machine: &'static str,
    pub object_type: &'static str,
    pub little_endian: bool,
    pub abi_matches: bool,
    pub has_load_segment: bool,
    pub has_dynamic_segment: bool,
    pub load_plan: Option<ElfLoadPlan>,
    pub relocation_types: BTreeMap<String, usize>,
    pub relocations: Vec<ElfRelocation>,
    pub needed: Vec<String>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub android_api_imports: BTreeMap<&'static str, usize>,
}

impl ElfReport {
    pub fn is_loadable_android_arm64_shared_object(&self) -> bool {
        self.class == "ELF64"
            && self.machine == "AArch64"
            && self.object_type == "ET_DYN"
            && self.little_endian
            && self.abi_matches
            && self.has_load_segment
            && self.has_dynamic_segment
            && self.load_plan.is_some()
    }
}

pub fn analyze(bytes: &[u8], abi: &str) -> Result<ElfReport> {
    let elf = Elf::parse(bytes).context("arquivo não é um ELF válido")?;
    let machine = machine_name(elf.header.e_machine);
    let object_type = match elf.header.e_type {
        header::ET_DYN => "ET_DYN",
        header::ET_EXEC => "ET_EXEC",
        header::ET_REL => "ET_REL",
        _ => "tipo ELF desconhecido",
    };
    let little_endian = elf.header.e_ident[header::EI_DATA] == header::ELFDATA2LSB;
    let has_load_segment = elf
        .program_headers
        .iter()
        .any(|segment| segment.p_type == program_header::PT_LOAD);
    let has_dynamic_segment = elf
        .program_headers
        .iter()
        .any(|segment| segment.p_type == program_header::PT_DYNAMIC);
    let load_segments = elf
        .program_headers
        .iter()
        .filter(|segment| segment.p_type == program_header::PT_LOAD)
        .map(|segment| {
            (
                segment.p_offset,
                segment.p_vaddr,
                segment.p_filesz,
                segment.p_memsz,
                segment.p_align,
                segment.p_flags,
            )
        })
        .collect::<Vec<_>>();
    let load_plan = if load_segments.is_empty() {
        None
    } else {
        Some(build_load_plan(bytes.len() as u64, &load_segments)?)
    };
    let relocations = elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .map(|relocation| {
            let symbol_name = elf
                .dynsyms
                .get(relocation.r_sym)
                .and_then(|symbol| elf.dynstrtab.get_at(symbol.st_name))
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            ElfRelocation {
                offset: relocation.r_offset,
                addend: relocation.r_addend,
                relocation_type: relocation.r_type,
                relocation_name: relocation_name(relocation.r_type),
                symbol_index: relocation.r_sym,
                symbol_name,
            }
        })
        .collect::<Vec<_>>();
    let mut relocation_types = BTreeMap::new();
    for relocation in &relocations {
        *relocation_types
            .entry(relocation.relocation_name.clone())
            .or_insert(0) += 1;
    }
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    for symbol in &elf.dynsyms {
        let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        if symbol.st_shndx == 0 {
            imports.push(name.to_owned());
        } else {
            exports.push(name.to_owned());
        }
    }

    let mut android_api_imports = BTreeMap::new();
    for symbol in &imports {
        if let Some(group) = android_api_group(symbol) {
            *android_api_imports.entry(group).or_insert(0) += 1;
        }
    }

    Ok(ElfReport {
        class: elf_class(elf.header.e_ident[header::EI_CLASS]),
        machine,
        object_type,
        little_endian,
        abi_matches: abi_matches_machine(abi, elf.header.e_machine),
        has_load_segment,
        has_dynamic_segment,
        load_plan,
        relocation_types,
        relocations,
        needed: elf
            .libraries
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        imports,
        exports,
        android_api_imports,
    })
}

pub fn apply_relative_relocations(
    image: &mut [u8],
    image_start: u64,
    load_bias: u64,
    relocations: &[ElfRelocation],
) -> Result<usize> {
    let mut writes = Vec::new();
    for relocation in relocations {
        if relocation.relocation_type != reloc::R_AARCH64_RELATIVE {
            anyhow::bail!(
                "relocation {} não é suportada nesta etapa",
                relocation.relocation_name
            );
        }
        if relocation.symbol_index != 0 {
            anyhow::bail!("R_AARCH64_RELATIVE deve usar índice de símbolo zero");
        }
        let addend = relocation
            .addend
            .context("R_AARCH64_RELATIVE exige addend explícito RELA")?;
        let image_offset = relocation
            .offset
            .checked_sub(image_start)
            .context("offset da relocation antecede o início da imagem")?;
        let start = usize::try_from(image_offset).context("offset ELF não cabe em usize")?;
        let end = start
            .checked_add(8)
            .context("overflow no campo de relocation ELF")?;
        if end > image.len() {
            anyhow::bail!("alvo de relocation excede a imagem mapeada");
        }
        let value = i128::from(load_bias) + i128::from(addend);
        let value = u64::try_from(value).context("resultado de R_AARCH64_RELATIVE excede u64")?;
        writes.push((start, value));
    }

    for (start, value) in &writes {
        image[*start..*start + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(writes.len())
}

fn relocation_name(relocation_type: u32) -> String {
    let name = match relocation_type {
        reloc::R_AARCH64_NONE => "R_AARCH64_NONE",
        reloc::R_AARCH64_ABS64 => "R_AARCH64_ABS64",
        reloc::R_AARCH64_ABS32 => "R_AARCH64_ABS32",
        reloc::R_AARCH64_PREL64 => "R_AARCH64_PREL64",
        reloc::R_AARCH64_PREL32 => "R_AARCH64_PREL32",
        reloc::R_AARCH64_GLOB_DAT => "R_AARCH64_GLOB_DAT",
        reloc::R_AARCH64_JUMP_SLOT => "R_AARCH64_JUMP_SLOT",
        reloc::R_AARCH64_RELATIVE => "R_AARCH64_RELATIVE",
        reloc::R_AARCH64_TLS_DTPMOD => "R_AARCH64_TLS_DTPMOD",
        reloc::R_AARCH64_TLS_DTPREL => "R_AARCH64_TLS_DTPREL",
        reloc::R_AARCH64_TLS_TPREL => "R_AARCH64_TLS_TPREL",
        reloc::R_AARCH64_TLSDESC => "R_AARCH64_TLSDESC",
        reloc::R_AARCH64_IRELATIVE => "R_AARCH64_IRELATIVE",
        _ => return format!("R_AARCH64_UNKNOWN_{relocation_type}"),
    };
    name.to_owned()
}

fn build_load_plan(
    file_size: u64,
    segments: &[(u64, u64, u64, u64, u64, u32)],
) -> Result<ElfLoadPlan> {
    let mut planned_segments = Vec::with_capacity(segments.len());
    for &(file_offset, virtual_address, segment_file_size, memory_size, alignment, flags) in
        segments
    {
        if segment_file_size > memory_size {
            anyhow::bail!("segmento PT_LOAD tem p_filesz maior que p_memsz");
        }
        let file_end = file_offset
            .checked_add(segment_file_size)
            .context("overflow no intervalo de arquivo do segmento PT_LOAD")?;
        if file_end > file_size {
            anyhow::bail!("segmento PT_LOAD excede o tamanho do ELF");
        }
        if file_offset % ELF_PAGE_SIZE != virtual_address % ELF_PAGE_SIZE {
            anyhow::bail!(
                "offset e endereço virtual não são compatíveis com mapeamento por página"
            );
        }
        if alignment > 1
            && (!alignment.is_power_of_two()
                || file_offset % alignment != virtual_address % alignment)
        {
            anyhow::bail!("alinhamento inválido no segmento PT_LOAD");
        }
        let virtual_end = virtual_address
            .checked_add(memory_size)
            .context("overflow no intervalo virtual do segmento PT_LOAD")?;
        let mapped_start = virtual_address & !(ELF_PAGE_SIZE - 1);
        let mapped_end = align_up(virtual_end, ELF_PAGE_SIZE)?;
        planned_segments.push(ElfLoadSegment {
            file_offset,
            virtual_address,
            file_size: segment_file_size,
            memory_size,
            alignment,
            mapped_start,
            mapped_end,
            readable: flags & program_header::PF_R != 0,
            writable: flags & program_header::PF_W != 0,
            executable: flags & program_header::PF_X != 0,
        });
    }

    let image_start = planned_segments
        .iter()
        .map(|segment| segment.mapped_start)
        .min()
        .context("ELF não contém segmentos PT_LOAD")?;
    let image_end = planned_segments
        .iter()
        .map(|segment| segment.mapped_end)
        .max()
        .context("ELF não contém segmentos PT_LOAD")?;
    let image_size = image_end
        .checked_sub(image_start)
        .context("intervalo virtual ELF inválido")?;

    Ok(ElfLoadPlan {
        page_size: ELF_PAGE_SIZE,
        image_start,
        image_end,
        image_size,
        segments: planned_segments,
    })
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    value
        .checked_add(alignment - 1)
        .map(|aligned| aligned & !(alignment - 1))
        .context("overflow ao alinhar o intervalo virtual ELF")
}

fn android_api_group(symbol: &str) -> Option<&'static str> {
    if symbol.starts_with("__android_log") {
        Some("Android logging")
    } else if symbol.starts_with("ANativeWindow_") {
        Some("Native window")
    } else if symbol.starts_with("AMedia") {
        Some("Media NDK")
    } else if symbol.starts_with("AAsset") || symbol.starts_with("AConfiguration") {
        Some("Assets/configuration NDK")
    } else if symbol.starts_with("ALooper_") || symbol.starts_with("AChoreographer_") {
        Some("Looper/frame callbacks")
    } else if has_lowercase_api_prefix(symbol, "egl") {
        Some("EGL")
    } else if has_lowercase_api_prefix(symbol, "gl") {
        Some("OpenGL ES")
    } else if symbol.starts_with("SL") || has_lowercase_api_prefix(symbol, "sl") {
        Some("OpenSL ES")
    } else if symbol.starts_with("A")
        && symbol.as_bytes().get(1).is_some_and(u8::is_ascii_uppercase)
    {
        Some("Other Android NDK")
    } else {
        None
    }
}

fn has_lowercase_api_prefix(symbol: &str, prefix: &str) -> bool {
    symbol
        .strip_prefix(prefix)
        .and_then(|suffix| suffix.as_bytes().first())
        .is_some_and(u8::is_ascii_uppercase)
}

pub fn import_group(symbol: &str) -> &'static str {
    if let Some(group) = android_api_group(symbol) {
        group
    } else if symbol.starts_with("JNI_") || symbol.starts_with("Java_") {
        "JNI"
    } else if symbol.starts_with("__cxa") || symbol.starts_with("_Z") || symbol.starts_with("__gxx")
    {
        "C++ runtime"
    } else if symbol.starts_with("pthread_") || symbol.starts_with("sem_") {
        "POSIX threads"
    } else {
        "Other ELF imports"
    }
}

fn elf_class(class: u8) -> &'static str {
    match class {
        header::ELFCLASS32 => "ELF32",
        header::ELFCLASS64 => "ELF64",
        _ => "classe ELF desconhecida",
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        header::EM_AARCH64 => "AArch64",
        header::EM_ARM => "ARM",
        header::EM_386 => "x86",
        header::EM_X86_64 => "x86_64",
        _ => "arquitetura desconhecida",
    }
}

fn abi_matches_machine(abi: &str, machine: u16) -> bool {
    match abi {
        "arm64-v8a" => machine == header::EM_AARCH64,
        "armeabi-v7a" | "armeabi" => machine == header::EM_ARM,
        "x86" => machine == header::EM_386,
        "x86_64" => machine == header::EM_X86_64,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_android_abi_against_elf_machine() {
        assert!(abi_matches_machine("arm64-v8a", header::EM_AARCH64));
        assert!(!abi_matches_machine("arm64-v8a", header::EM_X86_64));
    }

    #[test]
    fn accepts_only_arm64_dynamic_little_endian_elf_with_load_segments() {
        let report = ElfReport {
            class: "ELF64",
            machine: "AArch64",
            object_type: "ET_DYN",
            little_endian: true,
            abi_matches: true,
            has_load_segment: true,
            has_dynamic_segment: true,
            load_plan: Some(ElfLoadPlan {
                page_size: ELF_PAGE_SIZE,
                image_start: 0,
                image_end: ELF_PAGE_SIZE,
                image_size: ELF_PAGE_SIZE,
                segments: Vec::new(),
            }),
            relocation_types: BTreeMap::new(),
            relocations: Vec::new(),
            needed: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            android_api_imports: BTreeMap::new(),
        };
        assert!(report.is_loadable_android_arm64_shared_object());

        let incompatible = ElfReport {
            object_type: "ET_EXEC",
            ..report
        };
        assert!(!incompatible.is_loadable_android_arm64_shared_object());
    }

    #[test]
    fn creates_page_aligned_load_plan_and_tracks_segment_permissions() {
        let plan = build_load_plan(
            0x5000,
            &[
                (0x1000, 0x1000, 0x800, 0x1000, 0x1000, program_header::PF_R),
                (
                    0x3000,
                    0x3000,
                    0x1000,
                    0x1800,
                    0x1000,
                    program_header::PF_R | program_header::PF_W | program_header::PF_X,
                ),
            ],
        )
        .unwrap();

        assert_eq!(plan.page_size, 4096);
        assert_eq!(plan.image_start, 0x1000);
        assert_eq!(plan.image_end, 0x5000);
        assert_eq!(plan.image_size, 0x4000);
        assert_eq!(plan.segments.len(), 2);
        assert!(plan.segments[0].readable);
        assert!(!plan.segments[0].writable);
        assert!(plan.segments[1].writable && plan.segments[1].executable);
        assert_eq!(
            plan.segments[1].memory_size - plan.segments[1].file_size,
            0x800
        );
    }

    #[test]
    fn rejects_invalid_load_segment_ranges_and_alignment() {
        assert!(build_load_plan(0x1000, &[(0, 0, 0x800, 0x400, 1, program_header::PF_R)]).is_err());
        assert!(
            build_load_plan(0x1000, &[(0x800, 0, 0x900, 0x900, 1, program_header::PF_R)]).is_err()
        );
        assert!(
            build_load_plan(
                0x1000,
                &[(0x1000, 0, 0x100, 0x100, 3, program_header::PF_R)]
            )
            .is_err()
        );
        assert!(
            build_load_plan(0x1000, &[(0x100, 0, 0x100, 0x100, 1, program_header::PF_R)]).is_err()
        );
        assert!(build_load_plan(0x1000, &[]).is_err());
    }

    #[test]
    fn names_common_arm64_dynamic_relocations_and_preserves_unknown_types() {
        assert_eq!(
            relocation_name(reloc::R_AARCH64_RELATIVE),
            "R_AARCH64_RELATIVE"
        );
        assert_eq!(
            relocation_name(reloc::R_AARCH64_JUMP_SLOT),
            "R_AARCH64_JUMP_SLOT"
        );
        assert_eq!(relocation_name(12345), "R_AARCH64_UNKNOWN_12345");
    }

    #[test]
    fn applies_relative_relocations_using_load_bias_and_addend() {
        let relocations = [
            ElfRelocation {
                offset: 0x1010,
                addend: Some(0x40),
                relocation_type: reloc::R_AARCH64_RELATIVE,
                relocation_name: "R_AARCH64_RELATIVE".to_owned(),
                symbol_index: 0,
                symbol_name: None,
            },
            ElfRelocation {
                offset: 0x1018,
                addend: Some(-8),
                relocation_type: reloc::R_AARCH64_RELATIVE,
                relocation_name: "R_AARCH64_RELATIVE".to_owned(),
                symbol_index: 0,
                symbol_name: None,
            },
        ];
        let mut image = [0; 0x40];

        assert_eq!(
            apply_relative_relocations(&mut image, 0x1000, 0x7000, &relocations).unwrap(),
            2
        );
        assert_eq!(
            u64::from_le_bytes(image[0x10..0x18].try_into().unwrap()),
            0x7040
        );
        assert_eq!(
            u64::from_le_bytes(image[0x18..0x20].try_into().unwrap()),
            0x6ff8
        );
    }

    #[test]
    fn rejects_unsupported_or_invalid_relative_relocations_without_partial_writes() {
        let valid = ElfRelocation {
            offset: 0x1000,
            addend: Some(1),
            relocation_type: reloc::R_AARCH64_RELATIVE,
            relocation_name: "R_AARCH64_RELATIVE".to_owned(),
            symbol_index: 0,
            symbol_name: None,
        };
        let mut image = [0; 16];
        let invalid = ElfRelocation {
            offset: 0x1010,
            ..valid.clone()
        };
        assert!(
            apply_relative_relocations(&mut image, 0x1000, 0x2000, &[valid.clone(), invalid])
                .is_err()
        );
        assert_eq!(image, [0; 16]);
        assert!(
            apply_relative_relocations(
                &mut image,
                0x1000,
                0x2000,
                &[ElfRelocation {
                    addend: None,
                    ..valid.clone()
                }]
            )
            .is_err()
        );
        assert!(
            apply_relative_relocations(
                &mut image,
                0x1000,
                0x2000,
                &[ElfRelocation {
                    symbol_index: 1,
                    ..valid.clone()
                }]
            )
            .is_err()
        );
        assert!(
            apply_relative_relocations(
                &mut image,
                0x1000,
                0x2000,
                &[ElfRelocation {
                    relocation_type: reloc::R_AARCH64_JUMP_SLOT,
                    relocation_name: "R_AARCH64_JUMP_SLOT".to_owned(),
                    ..valid.clone()
                }]
            )
            .is_err()
        );
        assert!(
            apply_relative_relocations(
                &mut image,
                0x1000,
                0,
                &[ElfRelocation {
                    addend: Some(-1),
                    ..valid
                }]
            )
            .is_err()
        );
    }

    #[test]
    fn groups_android_native_import_families() {
        assert_eq!(import_group("ANativeWindow_fromSurface"), "Native window");
        assert_eq!(import_group("AMediaCodec_start"), "Media NDK");
        assert_eq!(import_group("eglInitialize"), "EGL");
        assert_eq!(import_group("glViewport"), "OpenGL ES");
        assert_eq!(import_group("sleep"), "Other ELF imports");
        assert_eq!(import_group("JNI_OnLoad"), "JNI");
        assert_eq!(import_group("__cxa_throw"), "C++ runtime");
        assert_eq!(import_group("pthread_create"), "POSIX threads");
        assert_eq!(import_group("arbitrary_symbol"), "Other ELF imports");
    }
}
