use anyhow::{Context, Result};
use goblin::elf::{Elf, header, program_header, reloc, section_header, sym};
use memmap2::{MmapMut, MmapOptions};
use std::collections::{BTreeMap, BTreeSet};

const ELF_PAGE_SIZE: u64 = 4096;
const DT_RELRSZ_TAG: u64 = 35;
const DT_RELR_TAG: u64 = 36;
const DT_RELRENT_TAG: u64 = 37;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfPageProtection {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ElfInitPlan {
    pub init: Option<u64>,
    pub init_array: Option<(u64, u64)>,
    pub fini: Option<u64>,
    pub fini_array: Option<(u64, u64)>,
}

#[derive(Clone, Debug)]
pub struct ElfTlsPlan {
    pub virtual_address: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

#[derive(Clone, Debug)]
pub struct ElfRelroPlan {
    pub virtual_address: u64,
    pub memory_size: u64,
    pub page_start: u64,
    pub page_end: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ResolvedElfInitPlan {
    pub init_functions: Vec<u64>,
    pub fini_functions: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct ElfRelocation {
    pub offset: u64,
    pub addend: Option<i64>,
    pub relocation_type: u32,
    pub relocation_name: String,
    pub symbol_index: usize,
    pub symbol_name: Option<String>,
    pub symbol_value: Option<u64>,
    pub symbol_defined: bool,
    pub symbol_absolute: bool,
    pub symbol_weak: bool,
    pub symbol_version: Option<ElfSymbolVersion>,
    pub symbol_version_unknown: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElfSymbolVersion {
    pub name: String,
    pub hash: u32,
    pub hidden: bool,
}

#[derive(Clone, Debug)]
pub struct ElfDynamicSymbol {
    pub name: String,
    pub value: u64,
    pub defined: bool,
    pub absolute: bool,
    pub global: bool,
    pub weak: bool,
    pub visible: bool,
    pub version: Option<ElfSymbolVersion>,
    pub version_unknown: bool,
}

pub struct MappedElfImage {
    mapping: MmapMut,
    pub load_bias: u64,
    pub relative_relocations_applied: usize,
    pub symbol_relocations_applied: usize,
    pub unresolved_relocation_count: usize,
    pub unresolved_relocations: Vec<String>,
    page_protections_applied: bool,
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
    pub init_plan: ElfInitPlan,
    pub tls_plan: Option<ElfTlsPlan>,
    pub relro_plans: Vec<ElfRelroPlan>,
    pub relocation_types: BTreeMap<String, usize>,
    pub relocations: Vec<ElfRelocation>,
    pub dynamic_symbols: Vec<ElfDynamicSymbol>,
    pub soname: Option<String>,
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

impl ElfLoadPlan {
    pub fn page_protection_plan(&self) -> Result<Vec<ElfPageProtection>> {
        let mut boundaries = vec![self.image_start, self.image_end];
        for segment in &self.segments {
            if segment.mapped_start < self.image_start
                || segment.mapped_end > self.image_end
                || segment.mapped_start >= segment.mapped_end
            {
                anyhow::bail!("intervalo PT_LOAD inválido para plano de proteção por página");
            }
            boundaries.push(segment.mapped_start);
            boundaries.push(segment.mapped_end);
        }
        boundaries.sort_unstable();
        boundaries.dedup();

        let mut ranges: Vec<ElfPageProtection> = Vec::new();
        for interval in boundaries.windows(2) {
            let [start, end] = [interval[0], interval[1]];
            if start == end {
                continue;
            }
            let covering = self
                .segments
                .iter()
                .filter(|segment| segment.mapped_start <= start && segment.mapped_end >= end);
            let mut protection = ElfPageProtection {
                start,
                end,
                readable: false,
                writable: false,
                executable: false,
            };
            for segment in covering {
                protection.readable |= segment.readable;
                protection.writable |= segment.writable;
                protection.executable |= segment.executable;
            }

            if let Some(previous) = ranges.last_mut()
                && previous.end == start
                && previous.readable == protection.readable
                && previous.writable == protection.writable
                && previous.executable == protection.executable
            {
                previous.end = end;
            } else {
                ranges.push(protection);
            }
        }
        Ok(ranges)
    }

    pub fn post_relro_page_protection_plan(
        &self,
        relro_plans: &[ElfRelroPlan],
    ) -> Result<Vec<ElfPageProtection>> {
        if self.page_size == 0 {
            anyhow::bail!("tamanho de página inválido para plano de proteção RELRO");
        }
        let protections = self.page_protection_plan()?;
        for relro in relro_plans {
            if relro.page_start % self.page_size != 0
                || relro.page_end % self.page_size != 0
                || relro.page_start < self.image_start
                || relro.page_end > self.image_end
                || relro.page_start >= relro.page_end
            {
                anyhow::bail!("intervalo PT_GNU_RELRO inválido para plano de proteção final");
            }
        }

        let mut final_protections: Vec<ElfPageProtection> = Vec::new();
        for protection in protections {
            let mut boundaries = vec![protection.start, protection.end];
            for relro in relro_plans {
                if relro.page_start > protection.start && relro.page_start < protection.end {
                    boundaries.push(relro.page_start);
                }
                if relro.page_end > protection.start && relro.page_end < protection.end {
                    boundaries.push(relro.page_end);
                }
            }
            boundaries.sort_unstable();
            boundaries.dedup();
            for interval in boundaries.windows(2) {
                let start = interval[0];
                let end = interval[1];
                let in_relro = relro_plans
                    .iter()
                    .any(|relro| start >= relro.page_start && end <= relro.page_end);
                let mut page = protection.clone();
                page.start = start;
                page.end = end;
                if in_relro {
                    page.writable = false;
                }
                if let Some(previous) = final_protections.last_mut()
                    && previous.end == page.start
                    && previous.readable == page.readable
                    && previous.writable == page.writable
                    && previous.executable == page.executable
                {
                    previous.end = page.end;
                } else {
                    final_protections.push(page);
                }
            }
        }
        Ok(final_protections)
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
    let init_plan = parse_init_plan(bytes, &elf)?;
    let tls_plan = parse_tls_plan(bytes.len() as u64, &elf.program_headers)?;
    let relro_plans = parse_relro_plans(bytes.len() as u64, &elf.program_headers)?;
    let symbol_versions = symbol_versions(&elf);
    let mut relocations = elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .map(|relocation| {
            let symbol = elf.dynsyms.get(relocation.r_sym);
            let symbol_name = symbol
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
                symbol_value: symbol.map(|symbol| symbol.st_value),
                symbol_defined: symbol.is_some_and(|symbol| symbol.st_shndx != 0),
                symbol_absolute: symbol
                    .is_some_and(|symbol| symbol.st_shndx == section_header::SHN_ABS as usize),
                symbol_weak: symbol
                    .is_some_and(|symbol| sym::st_bind(symbol.st_info) == sym::STB_WEAK),
                symbol_version: symbol_versions
                    .get(relocation.r_sym)
                    .and_then(|metadata| metadata.0.clone()),
                symbol_version_unknown: symbol_versions
                    .get(relocation.r_sym)
                    .is_some_and(|metadata| metadata.1),
            }
        })
        .collect::<Vec<_>>();
    if elf.header.e_machine == header::EM_AARCH64
        && elf.header.e_ident[header::EI_CLASS] == header::ELFCLASS64
        && little_endian
    {
        relocations.extend(parse_relr_relocations(bytes, &elf.program_headers, &elf)?);
    }
    let mut relocation_types = BTreeMap::new();
    for relocation in &relocations {
        *relocation_types
            .entry(relocation.relocation_name.clone())
            .or_insert(0) += 1;
    }
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut dynamic_symbols = Vec::new();

    for (symbol_index, symbol) in elf.dynsyms.iter().enumerate() {
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
        dynamic_symbols.push(ElfDynamicSymbol {
            name: name.to_owned(),
            value: symbol.st_value,
            defined: symbol.st_shndx != 0,
            absolute: symbol.st_shndx == section_header::SHN_ABS as usize,
            global: sym::st_bind(symbol.st_info) == sym::STB_GLOBAL,
            weak: sym::st_bind(symbol.st_info) == sym::STB_WEAK,
            visible: matches!(
                sym::st_visibility(symbol.st_other),
                sym::STV_DEFAULT | sym::STV_PROTECTED
            ),
            version: symbol_versions
                .get(symbol_index)
                .and_then(|metadata| metadata.0.clone()),
            version_unknown: symbol_versions
                .get(symbol_index)
                .is_some_and(|metadata| metadata.1),
        });
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
        init_plan,
        tls_plan,
        relro_plans,
        relocation_types,
        relocations,
        dynamic_symbols,
        soname: elf.soname.map(str::to_owned),
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

fn symbol_versions(elf: &Elf<'_>) -> Vec<(Option<ElfSymbolVersion>, bool)> {
    let mut versions = BTreeMap::<u16, (String, u32)>::new();
    if let Some(verneed) = &elf.verneed {
        for need in verneed {
            for auxiliary in &need {
                if let Some(name) = elf.dynstrtab.get_at(auxiliary.vna_name) {
                    versions.insert(
                        auxiliary.vna_other & 0x7fff,
                        (name.to_owned(), auxiliary.vna_hash),
                    );
                }
            }
        }
    }
    if let Some(verdef) = &elf.verdef {
        for definition in verdef {
            if let Some(auxiliary) = definition.iter().next()
                && let Some(name) = elf.dynstrtab.get_at(auxiliary.vda_name)
            {
                versions.insert(
                    definition.vd_ndx & 0x7fff,
                    (name.to_owned(), definition.vd_hash),
                );
            }
        }
    }

    let has_dynamic_versym = elf.dynamic.as_ref().is_some_and(|dynamic| {
        dynamic
            .dyns
            .iter()
            .any(|entry| entry.d_tag == goblin::elf::dynamic::DT_VERSYM)
    });
    elf.dynsyms
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let Some(versym) = elf
                .versym
                .as_ref()
                .and_then(|section| section.get_at(index))
            else {
                return (None, has_dynamic_versym);
            };
            if versym.is_global() || versym.is_local() {
                return (None, false);
            }
            match versions.get(&versym.version()) {
                Some((name, hash)) => (
                    Some(ElfSymbolVersion {
                        name: name.clone(),
                        hash: *hash,
                        hidden: versym.is_hidden(),
                    }),
                    false,
                ),
                None => (None, true),
            }
        })
        .collect()
}

fn decode_relr_entries(entries: &[u64]) -> Result<Vec<u64>> {
    let mut offsets = Vec::new();
    let mut next_address = None;

    for entry in entries {
        if entry & 1 == 0 {
            if entry % 8 != 0 {
                anyhow::bail!("entrada de endereço DT_RELR não está alinhada a 8 bytes");
            }
            offsets.push(*entry);
            next_address = Some(
                entry
                    .checked_add(8)
                    .context("overflow ao avançar endereço DT_RELR")?,
            );
            continue;
        }

        let base =
            next_address.context("bitmap DT_RELR aparece antes de uma entrada de endereço")?;
        for bit in 1..64 {
            if entry & (1_u64 << bit) != 0 {
                let offset = base
                    .checked_add((bit - 1) * 8)
                    .context("overflow ao decodificar bitmap DT_RELR")?;
                offsets.push(offset);
            }
        }
        next_address = Some(
            base.checked_add(63 * 8)
                .context("overflow ao avançar bitmap DT_RELR")?,
        );
    }

    Ok(offsets)
}

fn virtual_address_to_file_offset(
    address: u64,
    size: u64,
    program_headers: &[goblin::elf::ProgramHeader],
    file_size: usize,
) -> Result<usize> {
    for segment in program_headers
        .iter()
        .filter(|segment| segment.p_type == program_header::PT_LOAD)
    {
        let segment_end = segment
            .p_vaddr
            .checked_add(segment.p_filesz)
            .context("overflow no intervalo PT_LOAD ao ler DT_RELR")?;
        let requested_end = address
            .checked_add(size)
            .context("overflow no endereço virtual DT_RELR")?;
        if address < segment.p_vaddr || requested_end > segment_end {
            continue;
        }
        let file_offset = segment
            .p_offset
            .checked_add(address - segment.p_vaddr)
            .context("overflow no offset de arquivo DT_RELR")?;
        let file_end = file_offset
            .checked_add(size)
            .context("overflow no fim da tabela DT_RELR")?;
        if file_end > file_size as u64 {
            anyhow::bail!("tabela DT_RELR excede os limites do arquivo ELF");
        }
        return usize::try_from(file_offset).context("offset DT_RELR não cabe em usize");
    }
    anyhow::bail!("tabela DT_RELR não está contida em um PT_LOAD de arquivo")
}

fn dynamic_value(elf: &Elf<'_>, tag: u64) -> Result<Option<u64>> {
    let mut value = None;
    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            if entry.d_tag == tag && value.replace(entry.d_val).is_some() {
                anyhow::bail!("entrada dinâmica duplicada: {tag}");
            }
        }
    }
    Ok(value)
}

fn validate_executable_address(
    address: u64,
    program_headers: &[goblin::elf::ProgramHeader],
) -> Result<()> {
    if address == 0 {
        return Ok(());
    }
    if program_headers.iter().any(|segment| {
        segment.p_type == program_header::PT_LOAD
            && segment.p_flags & program_header::PF_X != 0
            && address >= segment.p_vaddr
            && address < segment.p_vaddr.saturating_add(segment.p_memsz)
    }) {
        return Ok(());
    }
    anyhow::bail!("função inicializadora/finalizadora não está em PT_LOAD executável")
}

fn dynamic_array(
    elf: &Elf<'_>,
    program_headers: &[goblin::elf::ProgramHeader],
    file_size: usize,
    address_tag: u64,
    size_tag: u64,
    pointer_size: u64,
) -> Result<Option<(u64, u64)>> {
    let address = dynamic_value(elf, address_tag)?;
    let size = dynamic_value(elf, size_tag)?;
    match (address, size) {
        (None, None) => Ok(None),
        (Some(address), Some(size)) => {
            if size % pointer_size != 0 {
                anyhow::bail!("array de inicializadores/finalizadores tem tamanho inválido");
            }
            if size > 0 {
                if address == 0 {
                    anyhow::bail!("array dinâmico não pode ter endereço zero");
                }
                virtual_address_to_file_offset(address, size, program_headers, file_size)?;
            }
            Ok(Some((address, size)))
        }
        _ => anyhow::bail!("endereço e tamanho do array dinâmico devem aparecer juntos"),
    }
}

fn parse_init_plan(bytes: &[u8], elf: &Elf<'_>) -> Result<ElfInitPlan> {
    let init = dynamic_value(elf, goblin::elf::dynamic::DT_INIT)?;
    let fini = dynamic_value(elf, goblin::elf::dynamic::DT_FINI)?;
    let pointer_size = match elf.header.e_ident[header::EI_CLASS] {
        header::ELFCLASS32 => 4,
        header::ELFCLASS64 => 8,
        _ => anyhow::bail!("classe ELF inválida para plano de inicializadores"),
    };
    for address in init.into_iter().chain(fini) {
        validate_executable_address(address, &elf.program_headers)?;
    }

    Ok(ElfInitPlan {
        init: init.filter(|address| *address != 0),
        init_array: dynamic_array(
            elf,
            &elf.program_headers,
            bytes.len(),
            goblin::elf::dynamic::DT_INIT_ARRAY,
            goblin::elf::dynamic::DT_INIT_ARRAYSZ,
            pointer_size,
        )?,
        fini: fini.filter(|address| *address != 0),
        fini_array: dynamic_array(
            elf,
            &elf.program_headers,
            bytes.len(),
            goblin::elf::dynamic::DT_FINI_ARRAY,
            goblin::elf::dynamic::DT_FINI_ARRAYSZ,
            pointer_size,
        )?,
    })
}

fn parse_tls_plan(
    file_size: u64,
    program_headers: &[goblin::elf::ProgramHeader],
) -> Result<Option<ElfTlsPlan>> {
    let mut tls = program_headers
        .iter()
        .filter(|segment| segment.p_type == program_header::PT_TLS);
    let Some(segment) = tls.next() else {
        return Ok(None);
    };
    if tls.next().is_some() {
        anyhow::bail!("ELF contém mais de um segmento PT_TLS");
    }
    if segment.p_filesz > segment.p_memsz {
        anyhow::bail!("segmento PT_TLS tem p_filesz maior que p_memsz");
    }
    let file_end = segment
        .p_offset
        .checked_add(segment.p_filesz)
        .context("overflow no intervalo de arquivo PT_TLS")?;
    if file_end > file_size {
        anyhow::bail!("segmento PT_TLS excede o tamanho do ELF");
    }
    let virtual_end = segment
        .p_vaddr
        .checked_add(segment.p_memsz)
        .context("overflow no intervalo virtual PT_TLS")?;
    if segment.p_align > 1
        && (!segment.p_align.is_power_of_two()
            || segment.p_offset % segment.p_align != segment.p_vaddr % segment.p_align)
    {
        anyhow::bail!("alinhamento inválido no segmento PT_TLS");
    }

    let contained_in_load_segment = program_headers
        .iter()
        .filter(|load| load.p_type == program_header::PT_LOAD)
        .any(|load| {
            let Some(load_file_end) = load.p_offset.checked_add(load.p_filesz) else {
                return false;
            };
            let Some(load_virtual_end) = load.p_vaddr.checked_add(load.p_memsz) else {
                return false;
            };
            segment.p_offset >= load.p_offset
                && segment.p_vaddr >= load.p_vaddr
                && segment.p_offset - load.p_offset == segment.p_vaddr - load.p_vaddr
                && file_end <= load_file_end
                && virtual_end <= load_virtual_end
        });
    if !contained_in_load_segment {
        anyhow::bail!("segmento PT_TLS não está contido em um PT_LOAD compatível");
    }

    Ok(Some(ElfTlsPlan {
        virtual_address: segment.p_vaddr,
        file_offset: segment.p_offset,
        file_size: segment.p_filesz,
        memory_size: segment.p_memsz,
        alignment: segment.p_align,
    }))
}

fn parse_relro_plans(
    file_size: u64,
    program_headers: &[goblin::elf::ProgramHeader],
) -> Result<Vec<ElfRelroPlan>> {
    let mut plans = Vec::new();
    for relro in program_headers
        .iter()
        .filter(|segment| segment.p_type == program_header::PT_GNU_RELRO)
    {
        if relro.p_filesz > relro.p_memsz {
            anyhow::bail!("segmento PT_GNU_RELRO tem p_filesz maior que p_memsz");
        }
        let file_end = relro
            .p_offset
            .checked_add(relro.p_filesz)
            .context("overflow no intervalo de arquivo PT_GNU_RELRO")?;
        if file_end > file_size {
            anyhow::bail!("segmento PT_GNU_RELRO excede o tamanho do ELF");
        }
        let virtual_end = relro
            .p_vaddr
            .checked_add(relro.p_memsz)
            .context("overflow no intervalo virtual PT_GNU_RELRO")?;
        let file_backed_by_load_segment = program_headers
            .iter()
            .filter(|segment| segment.p_type == program_header::PT_LOAD)
            .any(|load| {
                let Some(load_file_end) = load.p_offset.checked_add(load.p_filesz) else {
                    return false;
                };
                let Some(load_virtual_file_end) = load.p_vaddr.checked_add(load.p_filesz) else {
                    return false;
                };
                let Some(relro_file_virtual_end) = relro.p_vaddr.checked_add(relro.p_filesz) else {
                    return false;
                };
                relro.p_offset >= load.p_offset
                    && file_end <= load_file_end
                    && relro.p_vaddr >= load.p_vaddr
                    && relro_file_virtual_end <= load_virtual_file_end
                    && relro.p_vaddr - load.p_vaddr == relro.p_offset - load.p_offset
            });
        if !file_backed_by_load_segment {
            anyhow::bail!("dados de PT_GNU_RELRO não estão em um PT_LOAD compatível");
        }
        if relro.p_memsz == 0 {
            continue;
        }
        let page_start = relro.p_vaddr & !(ELF_PAGE_SIZE - 1);
        let page_end = align_up(virtual_end, ELF_PAGE_SIZE)?;
        let Some(image_start) = program_headers
            .iter()
            .filter(|segment| segment.p_type == program_header::PT_LOAD)
            .map(|segment| segment.p_vaddr & !(ELF_PAGE_SIZE - 1))
            .min()
        else {
            anyhow::bail!("PT_GNU_RELRO não pode existir sem PT_LOAD");
        };
        let image_end = program_headers
            .iter()
            .filter(|segment| segment.p_type == program_header::PT_LOAD)
            .filter_map(|segment| segment.p_vaddr.checked_add(segment.p_memsz))
            .map(|end| align_up(end, ELF_PAGE_SIZE))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .context("PT_LOAD sem fim virtual válido")?;
        if page_start < image_start || page_end > image_end {
            anyhow::bail!("intervalo em páginas PT_GNU_RELRO excede a imagem mapeável");
        }
        plans.push(ElfRelroPlan {
            virtual_address: relro.p_vaddr,
            memory_size: relro.p_memsz,
            page_start,
            page_end,
        });
    }
    plans.sort_by_key(|plan| (plan.page_start, plan.page_end));
    Ok(plans)
}

fn parse_relr_relocations(
    bytes: &[u8],
    program_headers: &[goblin::elf::ProgramHeader],
    elf: &Elf<'_>,
) -> Result<Vec<ElfRelocation>> {
    let Some(dynamic) = &elf.dynamic else {
        return Ok(Vec::new());
    };
    let mut relr_address = None;
    let mut relr_size = None;
    let mut relr_entry_size = None;
    for entry in &dynamic.dyns {
        let slot = match entry.d_tag {
            DT_RELR_TAG => &mut relr_address,
            DT_RELRSZ_TAG => &mut relr_size,
            DT_RELRENT_TAG => &mut relr_entry_size,
            _ => continue,
        };
        if slot.replace(entry.d_val).is_some() {
            anyhow::bail!("entrada DT_RELR duplicada");
        }
    }
    if relr_address.is_none() && relr_size.is_none() && relr_entry_size.is_none() {
        return Ok(Vec::new());
    }
    let address = relr_address.context("DT_RELR está ausente")?;
    let size = relr_size.context("DT_RELRSZ está ausente")?;
    let entry_size = relr_entry_size.context("DT_RELRENT está ausente")?;
    if entry_size != 8 || size % entry_size != 0 {
        anyhow::bail!("DT_RELRENT/DT_RELRSZ inválido para ELF64");
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    if address == 0 {
        anyhow::bail!("DT_RELR não pode apontar para endereço virtual zero");
    }
    let file_offset = virtual_address_to_file_offset(address, size, program_headers, bytes.len())?;
    let table_size = usize::try_from(size).context("tabela DT_RELR não cabe em usize")?;
    let table_end = file_offset
        .checked_add(table_size)
        .context("overflow no intervalo da tabela DT_RELR")?;
    let table = bytes
        .get(file_offset..table_end)
        .context("tabela DT_RELR excede o arquivo ELF")?;
    let entries = table
        .chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().expect("chunk tem oito bytes")))
        .collect::<Vec<_>>();
    let offsets = decode_relr_entries(&entries)?;
    Ok(offsets
        .into_iter()
        .map(|offset| ElfRelocation {
            offset,
            addend: None,
            relocation_type: reloc::R_AARCH64_RELATIVE,
            relocation_name: "R_AARCH64_RELATIVE_RELR".to_owned(),
            symbol_index: 0,
            symbol_name: None,
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: false,
            symbol_version: None,
            symbol_version_unknown: false,
        })
        .collect())
}

pub fn map_load_image(
    file_bytes: &[u8],
    plan: &ElfLoadPlan,
    max_image_size: u64,
) -> Result<MappedElfImage> {
    if plan.image_size > max_image_size {
        anyhow::bail!("imagem ELF excede o limite de materialização de {max_image_size} bytes");
    }
    let image_size = usize::try_from(plan.image_size)
        .context("imagem ELF não cabe no espaço de endereçamento")?;
    let mut mapping = MmapOptions::new()
        .len(image_size)
        .map_anon()
        .context("não foi possível mapear memória anônima para a imagem ELF")?;
    let mapping_address = mapping.as_ptr() as usize as u64;
    let load_bias = mapping_address
        .checked_sub(plan.image_start)
        .context("base mapeada não permite representar o load bias ELF")?;

    for segment in &plan.segments {
        let source_start =
            usize::try_from(segment.file_offset).context("offset ELF não cabe em usize")?;
        let source_end = source_start
            .checked_add(
                usize::try_from(segment.file_size)
                    .context("tamanho de segmento ELF não cabe em usize")?,
            )
            .context("overflow no intervalo de arquivo ELF")?;
        let target_start = usize::try_from(
            segment
                .virtual_address
                .checked_sub(plan.image_start)
                .context("segmento ELF antecede o início da imagem")?,
        )
        .context("endereço virtual ELF não cabe em usize")?;
        let target_end = target_start
            .checked_add(source_end - source_start)
            .context("overflow no intervalo de memória ELF")?;
        if source_end > file_bytes.len() || target_end > mapping.len() {
            anyhow::bail!("segmento PT_LOAD excede os limites do arquivo ou da imagem ELF");
        }
        mapping[target_start..target_end].copy_from_slice(&file_bytes[source_start..source_end]);
    }

    Ok(MappedElfImage {
        mapping,
        load_bias,
        relative_relocations_applied: 0,
        symbol_relocations_applied: 0,
        unresolved_relocation_count: 0,
        unresolved_relocations: Vec::new(),
        page_protections_applied: false,
    })
}

impl MappedElfImage {
    pub fn base_address(&self) -> u64 {
        self.mapping.as_ptr() as usize as u64
    }

    pub fn image_size(&self) -> usize {
        self.mapping.len()
    }

    pub fn bytes(&self) -> Result<&[u8]> {
        if self.page_protections_applied {
            anyhow::bail!("não é possível inspecionar bytes após proteger a imagem ELF");
        }
        Ok(&self.mapping)
    }

    pub fn apply_final_page_protections_without_execute(
        &mut self,
        plan: &ElfLoadPlan,
        relro_plans: &[ElfRelroPlan],
    ) -> Result<usize> {
        if self.page_protections_applied {
            anyhow::bail!("proteções finais da imagem ELF já foram aplicadas");
        }
        let protections = plan.post_relro_page_protection_plan(relro_plans)?;
        if plan.image_size != self.mapping.len() as u64 {
            anyhow::bail!("tamanho da imagem mapeada difere do plano de proteções");
        }
        self.page_protections_applied = true;
        for protection in &protections {
            let offset = usize::try_from(
                protection
                    .start
                    .checked_sub(plan.image_start)
                    .context("página protegida antecede a imagem ELF")?,
            )
            .context("offset de proteção não cabe em usize")?;
            let length = usize::try_from(
                protection
                    .end
                    .checked_sub(protection.start)
                    .context("intervalo de proteção inválido")?,
            )
            .context("tamanho da proteção não cabe em usize")?;
            let end = offset
                .checked_add(length)
                .context("overflow no intervalo de proteção ELF")?;
            if end > self.mapping.len() {
                anyhow::bail!("intervalo de proteção excede a imagem mapeada");
            }
            protect_memory(
                unsafe { self.mapping.as_ptr().add(offset) as *mut u8 },
                length,
                protection.readable,
                protection.writable,
            )?;
        }
        Ok(protections.len())
    }

    pub fn resolve_init_functions(
        &self,
        load_plan: &ElfLoadPlan,
        init_plan: &ElfInitPlan,
    ) -> Result<ResolvedElfInitPlan> {
        if self.page_protections_applied {
            anyhow::bail!("não é possível inspecionar inicializadores após proteger a imagem ELF");
        }
        fn resolve_address(address: u64, load_bias: u64, load_plan: &ElfLoadPlan) -> Result<u64> {
            let runtime_address = load_bias
                .checked_add(address)
                .context("endereço de inicializador excede u64")?;
            if load_plan.segments.iter().any(|segment| {
                segment.executable
                    && address >= segment.virtual_address
                    && address < segment.virtual_address.saturating_add(segment.memory_size)
            }) {
                Ok(runtime_address)
            } else {
                anyhow::bail!("inicializador ELF não aponta para PT_LOAD executável")
            }
        }

        fn read_function_array(
            image: &MappedElfImage,
            load_plan: &ElfLoadPlan,
            array: Option<(u64, u64)>,
        ) -> Result<Vec<u64>> {
            let Some((virtual_address, size)) = array else {
                return Ok(Vec::new());
            };
            let start = usize::try_from(
                virtual_address
                    .checked_sub(load_plan.image_start)
                    .context("array de inicializadores antecede a imagem ELF")?,
            )
            .context("offset do array de inicializadores não cabe em usize")?;
            let length = usize::try_from(size)
                .context("tamanho do array de inicializadores não cabe em usize")?;
            let end = start
                .checked_add(length)
                .context("overflow no intervalo do array de inicializadores")?;
            let bytes = image
                .mapping
                .get(start..end)
                .context("array de inicializadores excede a imagem mapeada")?;
            let mut functions = Vec::new();
            for entry in bytes.chunks_exact(8) {
                let address = u64::from_le_bytes(entry.try_into().expect("chunk tem oito bytes"));
                if address == 0 {
                    continue;
                }
                let executable = load_plan.segments.iter().any(|segment| {
                    let start = image.load_bias.saturating_add(segment.virtual_address);
                    let end = start.saturating_add(segment.memory_size);
                    segment.executable && address >= start && address < end
                });
                if !executable {
                    anyhow::bail!("array ELF contém função fora de PT_LOAD executável");
                }
                functions.push(address);
            }
            Ok(functions)
        }

        let mut init_functions = Vec::new();
        if let Some(init) = init_plan.init {
            init_functions.push(resolve_address(init, self.load_bias, load_plan)?);
        }
        init_functions.extend(read_function_array(self, load_plan, init_plan.init_array)?);

        let mut fini_functions = read_function_array(self, load_plan, init_plan.fini_array)?;
        fini_functions.reverse();
        if let Some(fini) = init_plan.fini {
            fini_functions.push(resolve_address(fini, self.load_bias, load_plan)?);
        }

        Ok(ResolvedElfInitPlan {
            init_functions,
            fini_functions,
        })
    }

    pub fn apply_relocations(
        &mut self,
        plan: &ElfLoadPlan,
        relocations: &[ElfRelocation],
        packaged_symbols: &BTreeMap<String, u64>,
    ) -> Result<()> {
        if self.page_protections_applied {
            anyhow::bail!("não é possível aplicar relocations após as proteções finais");
        }
        let mut writes = Vec::new();
        let mut unresolved = BTreeSet::new();
        let mut relative_count = 0;
        let mut symbol_count = 0;
        let mut unresolved_count = 0;

        for relocation in relocations {
            let (width, value, signed) = match relocation.relocation_type {
                reloc::R_AARCH64_NONE => continue,
                reloc::R_AARCH64_RELATIVE => {
                    if relocation.symbol_index != 0 {
                        anyhow::bail!("R_AARCH64_RELATIVE deve usar índice de símbolo zero");
                    }

                    let addend = match relocation.addend {
                        Some(addend) => i128::from(addend),
                        None if relocation.relocation_name == "R_AARCH64_RELATIVE_RELR" => {
                            let relative_offset =
                                relocation
                                    .offset
                                    .checked_sub(plan.image_start)
                                    .context("offset DT_RELR antecede o início da imagem")?;
                            let start = usize::try_from(relative_offset)
                                .context("offset DT_RELR não cabe em usize")?;
                            let end = start.checked_add(8).context("overflow no addend DT_RELR")?;
                            let addend = self
                                .mapping
                                .get(start..end)
                                .context("addend DT_RELR excede a imagem mapeada")?;
                            i128::from(u64::from_le_bytes(
                                addend.try_into().expect("slice tem oito bytes"),
                            ))
                        }
                        None => {
                            anyhow::bail!("R_AARCH64_RELATIVE exige addend explícito RELA")
                        }
                    };
                    let value = i128::from(self.load_bias) + addend;
                    (8, value, false)
                }
                reloc::R_AARCH64_ABS64
                | reloc::R_AARCH64_ABS32
                | reloc::R_AARCH64_ABS16
                | reloc::R_AARCH64_PREL64
                | reloc::R_AARCH64_PREL32
                | reloc::R_AARCH64_PREL16
                | reloc::R_AARCH64_GLOB_DAT
                | reloc::R_AARCH64_JUMP_SLOT => {
                    let symbol_name = relocation.symbol_name.as_deref();
                    let symbol_address = if relocation.symbol_defined {
                        let value = relocation
                            .symbol_value
                            .context("símbolo definido sem valor")?;
                        if relocation.symbol_absolute {
                            Some(value)
                        } else {
                            Some(
                                self.load_bias
                                    .checked_add(value)
                                    .context("endereço de símbolo ELF excede u64")?,
                            )
                        }
                    } else if relocation.symbol_index == 0 {
                        Some(0)
                    } else if relocation.symbol_version_unknown {
                        None
                    } else {
                        symbol_name.and_then(|name| {
                            packaged_symbols
                                .get(&symbol_lookup_key(name, relocation.symbol_version.as_ref()))
                                .copied()
                        })
                    };
                    let symbol_address = match symbol_address {
                        Some(address) => address,
                        None if relocation.symbol_weak && !relocation.symbol_version_unknown => 0,
                        None => {
                            unresolved.insert(
                                symbol_name
                                    .map(|name| {
                                        if relocation.symbol_version_unknown {
                                            format!("{name}@<versão ELF não decodificada>")
                                        } else {
                                            match relocation.symbol_version.as_ref() {
                                                Some(version) => {
                                                    format!("{name}@{}", version.name)
                                                }
                                                None => name.to_owned(),
                                            }
                                        }
                                    })
                                    .unwrap_or_else(|| relocation.relocation_name.clone()),
                            );
                            unresolved_count += 1;
                            continue;
                        }
                    };
                    let addend = i128::from(relocation.addend.unwrap_or(0));
                    let is_prel = matches!(
                        relocation.relocation_type,
                        reloc::R_AARCH64_PREL64 | reloc::R_AARCH64_PREL32 | reloc::R_AARCH64_PREL16
                    );
                    let place = i128::from(self.load_bias)
                        .checked_add(i128::from(relocation.offset))
                        .context("endereço alvo de relocation excede u64")?;
                    let value =
                        i128::from(symbol_address) + addend - if is_prel { place } else { 0 };
                    let width = match relocation.relocation_type {
                        reloc::R_AARCH64_ABS16 | reloc::R_AARCH64_PREL16 => 2,
                        reloc::R_AARCH64_ABS32 | reloc::R_AARCH64_PREL32 => 4,
                        _ => 8,
                    };
                    (width, value, is_prel)
                }
                _ => {
                    unresolved.insert(format!(
                        "{} ({})",
                        relocation.relocation_name,
                        relocation.symbol_name.as_deref().unwrap_or("(sem símbolo)")
                    ));
                    unresolved_count += 1;
                    continue;
                }
            };

            let bytes = encode_relocation_value(value, width, signed, &relocation.relocation_name)?;
            let target_end = relocation
                .offset
                .checked_add(width as u64)
                .context("overflow no endereço alvo de relocation")?;
            if !plan.segments.iter().any(|segment| {
                segment.writable
                    && relocation.offset >= segment.virtual_address
                    && target_end <= segment.virtual_address.saturating_add(segment.memory_size)
            }) {
                anyhow::bail!(
                    "alvo de {} não pertence a um PT_LOAD gravável",
                    relocation.relocation_name
                );
            }
            let relative_offset = relocation
                .offset
                .checked_sub(plan.image_start)
                .context("offset de relocation antecede o início da imagem")?;
            let start = usize::try_from(relative_offset)
                .context("offset de relocation não cabe em usize")?;
            let end = start
                .checked_add(width)
                .context("overflow no campo da relocation")?;
            if end > self.mapping.len() {
                anyhow::bail!("alvo de relocation excede a imagem mapeada");
            }
            writes.push((start, bytes));
            if relocation.relocation_type == reloc::R_AARCH64_RELATIVE {
                relative_count += 1;
            } else {
                symbol_count += 1;
            }
        }

        for (start, bytes) in &writes {
            self.mapping[*start..*start + bytes.len()].copy_from_slice(bytes);
        }
        self.relative_relocations_applied += relative_count;
        self.symbol_relocations_applied += symbol_count;
        self.unresolved_relocation_count = unresolved_count;
        self.unresolved_relocations = unresolved.into_iter().collect();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn protect_memory(address: *mut u8, length: usize, readable: bool, writable: bool) -> Result<()> {
    use std::ffi::c_void;

    const PROT_NONE: i32 = 0;
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;

    unsafe extern "C" {
        fn mprotect(address: *mut c_void, length: usize, protection: i32) -> i32;
    }

    let mut protection = PROT_NONE;
    if readable {
        protection |= PROT_READ;
    }
    if writable {
        protection |= PROT_WRITE;
    }
    let result = unsafe { mprotect(address.cast(), length, protection) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("mprotect falhou ao aplicar proteções ELF");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn protect_memory(address: *mut u8, length: usize, readable: bool, writable: bool) -> Result<()> {
    use std::ffi::c_void;

    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;

    unsafe extern "system" {
        fn VirtualProtect(
            address: *mut c_void,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
    }

    let protection = match (readable, writable) {
        (false, _) => PAGE_NOACCESS,
        (true, true) => PAGE_READWRITE,
        (true, false) => PAGE_READONLY,
    };
    let mut old_protection = 0;
    let result = unsafe { VirtualProtect(address.cast(), length, protection, &mut old_protection) };
    if result == 0 {
        return Err(std::io::Error::last_os_error())
            .context("VirtualProtect falhou ao aplicar proteções ELF");
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn protect_memory(
    _address: *mut u8,
    _length: usize,
    _readable: bool,
    _writable: bool,
) -> Result<()> {
    anyhow::bail!("aplicação de proteções ELF não é suportada nesta plataforma")
}

pub fn symbol_lookup_key(name: &str, version: Option<&ElfSymbolVersion>) -> String {
    match version {
        Some(version) => format!("{name}\0{}:{:08x}", version.name, version.hash),
        None => name.to_owned(),
    }
}

fn encode_relocation_value(
    value: i128,
    width: usize,
    signed: bool,
    relocation_name: &str,
) -> Result<Vec<u8>> {
    if signed {
        let value = match width {
            2 => i16::try_from(value)
                .map(i64::from)
                .context("resultado não cabe em relocation PREL16")?,
            4 => i32::try_from(value)
                .map(i64::from)
                .context("resultado não cabe em relocation PREL32")?,
            8 => i64::try_from(value).context("resultado não cabe em relocation PREL64")?,
            _ => anyhow::bail!("largura inválida para relocation {relocation_name}"),
        };
        let bytes = value.to_le_bytes();
        Ok(bytes[..width].to_vec())
    } else {
        let value = match width {
            2 => u16::try_from(value)
                .map(u64::from)
                .context("resultado não cabe em relocation ABS16")?,
            4 => u32::try_from(value)
                .map(u64::from)
                .context("resultado não cabe em relocation ABS32")?,
            8 => u64::try_from(value)
                .with_context(|| format!("resultado de {relocation_name} excede u64"))?,
            _ => anyhow::bail!("largura inválida para relocation {relocation_name}"),
        };
        let bytes = value.to_le_bytes();
        Ok(bytes[..width].to_vec())
    }
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
        reloc::R_AARCH64_ABS16 => "R_AARCH64_ABS16",
        reloc::R_AARCH64_PREL64 => "R_AARCH64_PREL64",
        reloc::R_AARCH64_PREL32 => "R_AARCH64_PREL32",
        reloc::R_AARCH64_PREL16 => "R_AARCH64_PREL16",
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
            init_plan: ElfInitPlan::default(),
            tls_plan: None,
            relro_plans: Vec::new(),
            relocation_types: BTreeMap::new(),
            relocations: Vec::new(),
            dynamic_symbols: Vec::new(),
            soname: None,
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
        assert_eq!(
            plan.page_protection_plan().unwrap(),
            vec![
                ElfPageProtection {
                    start: 0x1000,
                    end: 0x2000,
                    readable: true,
                    writable: false,
                    executable: false,
                },
                ElfPageProtection {
                    start: 0x2000,
                    end: 0x3000,
                    readable: false,
                    writable: false,
                    executable: false,
                },
                ElfPageProtection {
                    start: 0x3000,
                    end: 0x5000,
                    readable: true,
                    writable: true,
                    executable: true,
                },
            ]
        );
        let relro = [ElfRelroPlan {
            virtual_address: 0x3000,
            memory_size: 0x1000,
            page_start: 0x3000,
            page_end: 0x4000,
        }];
        let final_protections = plan.post_relro_page_protection_plan(&relro).unwrap();
        assert!(final_protections[2].readable);
        assert!(!final_protections[2].writable);
        assert!(final_protections[2].executable);
        assert!(
            plan.post_relro_page_protection_plan(&[ElfRelroPlan {
                page_start: 0x2001,
                page_end: 0x3000,
                ..relro[0].clone()
            }])
            .is_err()
        );
    }

    #[test]
    fn unions_permissions_when_load_segments_share_a_page() {
        let plan = build_load_plan(
            0x4000,
            &[
                (0x1000, 0x1000, 0x1000, 0x1000, 0x1000, program_header::PF_R),
                (0x2f00, 0x1f00, 0x100, 0x100, 1, program_header::PF_W),
            ],
        )
        .unwrap();

        assert_eq!(
            plan.page_protection_plan().unwrap(),
            vec![ElfPageProtection {
                start: 0x1000,
                end: 0x2000,
                readable: true,
                writable: true,
                executable: false,
            }]
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
    fn decodes_relr_address_and_bitmap_entries_with_checked_offsets() {
        let entries = [0x1000, (1 << 1) | (1 << 4) | 1, 0x1200];
        assert_eq!(
            decode_relr_entries(&entries).unwrap(),
            vec![0x1000, 0x1008, 0x1020, 0x1200]
        );
        assert!(decode_relr_entries(&[1]).is_err());
        assert!(decode_relr_entries(&[0x1001]).is_err());
        assert!(decode_relr_entries(&[u64::MAX - 7]).is_err());
    }

    #[test]
    fn reads_dt_relr_table_from_an_elf_load_segment() {
        let mut bytes = vec![0; 0x200];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = header::ELFCLASS64;
        bytes[5] = header::ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&header::ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&header::EM_AARCH64.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&3_u16.to_le_bytes());
        write_test_program_header(&mut bytes, 64, 1, 7, 0, 0, 0x200, 0x200, 0x1000);
        write_test_program_header(&mut bytes, 120, 2, 6, 0x100, 0x100, 128, 128, 8);
        write_test_program_header(
            &mut bytes,
            176,
            program_header::PT_TLS,
            4,
            0x1d0,
            0x1d0,
            16,
            32,
            8,
        );
        let dynamic_entries: [(u64, u64); 8] = [
            (DT_RELR_TAG, 0x180),
            (DT_RELRSZ_TAG, 16),
            (DT_RELRENT_TAG, 8),
            (goblin::elf::dynamic::DT_INIT, 0x40),
            (goblin::elf::dynamic::DT_INIT_ARRAY, 0x1c0),
            (goblin::elf::dynamic::DT_INIT_ARRAYSZ, 16),
            (goblin::elf::dynamic::DT_FINI, 0x48),
            (0, 0),
        ];
        for (index, (tag, value)) in dynamic_entries.into_iter().enumerate() {
            let offset = 0x100 + index * 16;
            bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x180..0x188].copy_from_slice(&0x20_u64.to_le_bytes());
        bytes[0x188..0x190].copy_from_slice(&(1_u64 | (1 << 2)).to_le_bytes());

        let elf = Elf::parse(&bytes).unwrap();
        let relr = parse_relr_relocations(&bytes, &elf.program_headers, &elf).unwrap();
        let init_plan = parse_init_plan(&bytes, &elf).unwrap();
        let tls_plan = parse_tls_plan(bytes.len() as u64, &elf.program_headers)
            .unwrap()
            .unwrap();

        assert_eq!(
            relr.iter()
                .map(|relocation| relocation.offset)
                .collect::<Vec<_>>(),
            vec![0x20, 0x30]
        );
        assert!(relr.iter().all(|relocation| {
            relocation.relocation_name == "R_AARCH64_RELATIVE_RELR" && relocation.addend.is_none()
        }));
        assert_eq!(init_plan.init, Some(0x40));
        assert_eq!(init_plan.init_array, Some((0x1c0, 16)));
        assert_eq!(init_plan.fini, Some(0x48));
        assert_eq!(init_plan.fini_array, None);
        assert_eq!(tls_plan.virtual_address, 0x1d0);
        assert_eq!(tls_plan.file_offset, 0x1d0);
        assert_eq!(tls_plan.file_size, 16);
        assert_eq!(tls_plan.memory_size, 32);
        assert_eq!(tls_plan.alignment, 8);

        let mut invalid_init_address = bytes.clone();
        invalid_init_address[0x100 + 3 * 16 + 8..0x100 + 4 * 16]
            .copy_from_slice(&0x300_u64.to_le_bytes());
        let invalid_init_elf = Elf::parse(&invalid_init_address).unwrap();
        assert!(parse_init_plan(&invalid_init_address, &invalid_init_elf).is_err());

        let mut invalid_array_size = bytes.clone();
        invalid_array_size[0x100 + 5 * 16 + 8..0x100 + 6 * 16]
            .copy_from_slice(&12_u64.to_le_bytes());
        let invalid_array_elf = Elf::parse(&invalid_array_size).unwrap();
        assert!(parse_init_plan(&invalid_array_size, &invalid_array_elf).is_err());

        let mut invalid_tls_size = bytes.clone();
        invalid_tls_size[176 + 32..176 + 40].copy_from_slice(&33_u64.to_le_bytes());
        let invalid_tls_elf = Elf::parse(&invalid_tls_size).unwrap();
        assert!(
            parse_tls_plan(
                invalid_tls_size.len() as u64,
                &invalid_tls_elf.program_headers
            )
            .is_err()
        );

        let mut invalid_tls_alignment = bytes.clone();
        invalid_tls_alignment[176 + 48..176 + 56].copy_from_slice(&3_u64.to_le_bytes());
        let invalid_tls_elf = Elf::parse(&invalid_tls_alignment).unwrap();
        assert!(
            parse_tls_plan(
                invalid_tls_alignment.len() as u64,
                &invalid_tls_elf.program_headers
            )
            .is_err()
        );
    }

    #[test]
    fn validates_gnu_relro_ranges_and_page_rounding() {
        let headers = [
            goblin::elf::ProgramHeader {
                p_type: program_header::PT_LOAD,
                p_offset: 0,
                p_vaddr: 0,
                p_filesz: 0x3000,
                p_memsz: 0x4000,
                ..Default::default()
            },
            goblin::elf::ProgramHeader {
                p_type: program_header::PT_GNU_RELRO,
                p_offset: 0x1a0,
                p_vaddr: 0x1a0,
                p_filesz: 0x820,
                p_memsz: 0x920,
                ..Default::default()
            },
        ];
        let plans = parse_relro_plans(0x3000, &headers).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].virtual_address, 0x1a0);
        assert_eq!(plans[0].memory_size, 0x920);
        assert_eq!(plans[0].page_start, 0);
        assert_eq!(plans[0].page_end, 0x1000);

        let invalid = [
            headers[0].clone(),
            goblin::elf::ProgramHeader {
                p_vaddr: 0x3f00,
                p_offset: 0x3f00,
                p_filesz: 0x100,
                p_memsz: 0x200,
                ..headers[1].clone()
            },
        ];
        assert!(parse_relro_plans(0x4000, &invalid).is_err());
    }

    fn write_test_program_header(
        bytes: &mut [u8],
        offset: usize,
        kind: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        bytes[offset..offset + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[offset + 4..offset + 8].copy_from_slice(&flags.to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&file_offset.to_le_bytes());
        bytes[offset + 16..offset + 24].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[offset + 24..offset + 32].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[offset + 32..offset + 40].copy_from_slice(&file_size.to_le_bytes());
        bytes[offset + 40..offset + 48].copy_from_slice(&memory_size.to_le_bytes());
        bytes[offset + 48..offset + 56].copy_from_slice(&alignment.to_le_bytes());
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
                symbol_value: None,
                symbol_defined: false,
                symbol_absolute: false,
                symbol_weak: false,
                symbol_version: None,
                symbol_version_unknown: false,
            },
            ElfRelocation {
                offset: 0x1018,
                addend: Some(-8),
                relocation_type: reloc::R_AARCH64_RELATIVE,
                relocation_name: "R_AARCH64_RELATIVE".to_owned(),
                symbol_index: 0,
                symbol_name: None,
                symbol_value: None,
                symbol_defined: false,
                symbol_absolute: false,
                symbol_weak: false,
                symbol_version: None,
                symbol_version_unknown: false,
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
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: false,
            symbol_version: None,
            symbol_version_unknown: false,
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
    fn maps_load_segments_copies_file_data_zeros_bss_and_applies_relocations() {
        let file_bytes = [0xabu8; 0x80];
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0x1000,
            image_end: 0x2000,
            image_size: 0x1000,
            segments: vec![ElfLoadSegment {
                file_offset: 0x20,
                virtual_address: 0x1100,
                file_size: 0x20,
                memory_size: 0x30,
                alignment: 0x1000,
                mapped_start: 0x1000,
                mapped_end: 0x2000,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let relative = ElfRelocation {
            offset: 0x1110,
            addend: Some(0x30),
            relocation_type: reloc::R_AARCH64_RELATIVE,
            relocation_name: "R_AARCH64_RELATIVE".to_owned(),
            symbol_index: 0,
            symbol_name: None,
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: false,
            symbol_version: None,
            symbol_version_unknown: false,
        };
        let unresolved = ElfRelocation {
            symbol_index: 1,
            symbol_name: Some("external_symbol".to_owned()),
            relocation_type: reloc::R_AARCH64_JUMP_SLOT,
            relocation_name: "R_AARCH64_JUMP_SLOT".to_owned(),
            ..relative.clone()
        };

        let mut image = map_load_image(&file_bytes, &plan, 0x1000).unwrap();
        let load_bias = image.load_bias;
        image
            .apply_relocations(&plan, &[relative, unresolved], &BTreeMap::new())
            .unwrap();

        assert_eq!(image.image_size(), 0x1000);
        assert!(
            image.bytes().unwrap()[..0x100]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert!(
            image.bytes().unwrap()[0x100..0x110]
                .iter()
                .all(|byte| *byte == 0xab)
        );
        assert_eq!(
            u64::from_le_bytes(image.bytes().unwrap()[0x110..0x118].try_into().unwrap()),
            load_bias + 0x30
        );
        assert!(
            image.bytes().unwrap()[0x118..0x120]
                .iter()
                .all(|byte| *byte == 0xab)
        );
        assert!(
            image.bytes().unwrap()[0x120..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(image.relative_relocations_applied, 1);
        assert_eq!(
            image.unresolved_relocations,
            vec!["external_symbol".to_owned()]
        );
    }

    #[test]
    fn applies_read_only_non_executable_memory_protections() {
        let file_bytes = vec![0x5a; ELF_PAGE_SIZE as usize];
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0x1000,
            image_end: 0x2000,
            image_size: ELF_PAGE_SIZE,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0x1000,
                file_size: ELF_PAGE_SIZE,
                memory_size: ELF_PAGE_SIZE,
                alignment: ELF_PAGE_SIZE,
                mapped_start: 0x1000,
                mapped_end: 0x2000,
                readable: true,
                writable: false,
                executable: true,
            }],
        };
        let mut image = map_load_image(&file_bytes, &plan, ELF_PAGE_SIZE).unwrap();
        assert_eq!(
            image
                .apply_final_page_protections_without_execute(&plan, &[])
                .unwrap(),
            1
        );
        assert!(image.bytes().is_err());
        assert!(
            image
                .apply_final_page_protections_without_execute(&plan, &[])
                .is_err()
        );
        assert!(
            image
                .apply_relocations(&plan, &[], &BTreeMap::new())
                .is_err()
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_applies_real_page_permissions_and_relro_without_execute() {
        use std::ffi::c_void;

        const PAGE_READONLY: u32 = 0x02;
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;

        #[repr(C)]
        struct MemoryBasicInformation {
            base_address: *mut c_void,
            allocation_base: *mut c_void,
            allocation_protect: u32,
            partition_id: u16,
            region_size: usize,
            state: u32,
            protect: u32,
            kind: u32,
        }

        unsafe extern "system" {
            fn VirtualQuery(
                address: *const c_void,
                information: *mut MemoryBasicInformation,
                length: usize,
            ) -> usize;
        }

        fn protection_at(address: u64) -> u32 {
            let mut information = MemoryBasicInformation {
                base_address: std::ptr::null_mut(),
                allocation_base: std::ptr::null_mut(),
                allocation_protect: 0,
                partition_id: 0,
                region_size: 0,
                state: 0,
                protect: 0,
                kind: 0,
            };
            let result = unsafe {
                VirtualQuery(
                    address as usize as *const c_void,
                    &mut information,
                    std::mem::size_of::<MemoryBasicInformation>(),
                )
            };
            assert_ne!(result, 0, "VirtualQuery falhou");
            information.protect
        }

        let page = ELF_PAGE_SIZE;
        let plan = ElfLoadPlan {
            page_size: page,
            image_start: 0x1000,
            image_end: 0x4000,
            image_size: page * 3,
            segments: vec![
                ElfLoadSegment {
                    file_offset: 0,
                    virtual_address: 0x1000,
                    file_size: page,
                    memory_size: page,
                    alignment: page,
                    mapped_start: 0x1000,
                    mapped_end: 0x2000,
                    readable: true,
                    writable: false,
                    executable: true,
                },
                ElfLoadSegment {
                    file_offset: page,
                    virtual_address: 0x2000,
                    file_size: page,
                    memory_size: page,
                    alignment: page,
                    mapped_start: 0x2000,
                    mapped_end: 0x3000,
                    readable: true,
                    writable: true,
                    executable: false,
                },
                ElfLoadSegment {
                    file_offset: page * 2,
                    virtual_address: 0x3000,
                    file_size: page,
                    memory_size: page,
                    alignment: page,
                    mapped_start: 0x3000,
                    mapped_end: 0x4000,
                    readable: true,
                    writable: true,
                    executable: false,
                },
            ],
        };
        let relro = [ElfRelroPlan {
            virtual_address: 0x2000,
            memory_size: page,
            page_start: 0x2000,
            page_end: 0x3000,
        }];
        let bytes = vec![0x5a; (page * 3) as usize];
        let mut image = map_load_image(&bytes, &plan, page * 3).unwrap();
        let base = image.base_address();
        image
            .apply_final_page_protections_without_execute(&plan, &relro)
            .unwrap();

        let first_page = protection_at(base) & 0xff;
        let relro_page = protection_at(base + page) & 0xff;
        let writable_page = protection_at(base + page * 2) & 0xff;
        assert_eq!(first_page, PAGE_READONLY);
        assert_eq!(relro_page, PAGE_READONLY);
        assert_eq!(writable_page, PAGE_READWRITE);
        assert!(
            [first_page, relro_page, writable_page]
                .iter()
                .all(|protection| {
                    ![PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE].contains(protection)
                })
        );
    }

    #[test]
    fn applies_relr_relocations_using_implicit_addends_from_image_memory() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0x1000,
            image_end: 0x2000,
            image_size: 0x1000,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0x1000,
                file_size: 0x40,
                memory_size: 0x40,
                alignment: 1,
                mapped_start: 0x1000,
                mapped_end: 0x2000,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let mut file_bytes = vec![0; 0x40];
        file_bytes[0x10..0x18].copy_from_slice(&0x1234_u64.to_le_bytes());
        let relocation = ElfRelocation {
            offset: 0x1010,
            addend: None,
            relocation_type: reloc::R_AARCH64_RELATIVE,
            relocation_name: "R_AARCH64_RELATIVE_RELR".to_owned(),
            symbol_index: 0,
            symbol_name: None,
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: false,
            symbol_version: None,
            symbol_version_unknown: false,
        };
        let mut image = map_load_image(&file_bytes, &plan, ELF_PAGE_SIZE).unwrap();
        let load_bias = image.load_bias;

        image
            .apply_relocations(&plan, &[relocation], &BTreeMap::new())
            .unwrap();

        assert_eq!(
            u64::from_le_bytes(image.bytes().unwrap()[0x10..0x18].try_into().unwrap()),
            load_bias + 0x1234
        );
        assert_eq!(image.relative_relocations_applied, 1);
    }

    #[test]
    fn resolves_initializer_and_finalizer_order_without_executing_functions() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0,
            image_end: ELF_PAGE_SIZE,
            image_size: ELF_PAGE_SIZE,
            segments: vec![
                ElfLoadSegment {
                    file_offset: 0,
                    virtual_address: 0,
                    file_size: 0x100,
                    memory_size: 0x100,
                    alignment: 1,
                    mapped_start: 0,
                    mapped_end: ELF_PAGE_SIZE,
                    readable: true,
                    writable: false,
                    executable: true,
                },
                ElfLoadSegment {
                    file_offset: 0x100,
                    virtual_address: 0x100,
                    file_size: 0x100,
                    memory_size: 0x100,
                    alignment: 1,
                    mapped_start: 0,
                    mapped_end: ELF_PAGE_SIZE,
                    readable: true,
                    writable: true,
                    executable: false,
                },
            ],
        };
        let mut image = map_load_image(&[0; 0x200], &plan, ELF_PAGE_SIZE).unwrap();
        let bias = image.load_bias;
        image.mapping[0x110..0x118].copy_from_slice(&(bias + 0x40).to_le_bytes());
        image.mapping[0x118..0x120].copy_from_slice(&0_u64.to_le_bytes());
        image.mapping[0x120..0x128].copy_from_slice(&(bias + 0x50).to_le_bytes());
        image.mapping[0x130..0x138].copy_from_slice(&(bias + 0x60).to_le_bytes());
        image.mapping[0x138..0x140].copy_from_slice(&(bias + 0x70).to_le_bytes());
        let init_plan = ElfInitPlan {
            init: Some(0x20),
            init_array: Some((0x110, 24)),
            fini: Some(0x80),
            fini_array: Some((0x130, 16)),
        };

        let functions = image.resolve_init_functions(&plan, &init_plan).unwrap();

        assert_eq!(
            functions.init_functions,
            vec![bias + 0x20, bias + 0x40, bias + 0x50]
        );
        assert_eq!(
            functions.fini_functions,
            vec![bias + 0x70, bias + 0x60, bias + 0x80]
        );
    }

    #[test]
    fn mapping_rejects_oversized_images_and_out_of_bounds_segments() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0,
            image_end: 0x1000,
            image_size: 0x1000,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0,
                file_size: 8,
                memory_size: 8,
                alignment: 1,
                mapped_start: 0,
                mapped_end: 0x1000,
                readable: true,
                writable: false,
                executable: false,
            }],
        };
        assert!(map_load_image(&[0; 8], &plan, 0x800).is_err());
        assert!(map_load_image(&[0; 4], &plan, 0x1000).is_err());
    }

    #[test]
    fn resolves_symbol_relocations_from_packaged_library_exports() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0x1000,
            image_end: 0x2000,
            image_size: 0x1000,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0x1000,
                file_size: 0x100,
                memory_size: 0x100,
                alignment: 1,
                mapped_start: 0x1000,
                mapped_end: 0x2000,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let relocations = [
            ElfRelocation {
                offset: 0x1010,
                addend: Some(8),
                relocation_type: reloc::R_AARCH64_ABS64,
                relocation_name: "R_AARCH64_ABS64".to_owned(),
                symbol_index: 1,
                symbol_name: Some("packaged_data".to_owned()),
                symbol_value: None,
                symbol_defined: false,
                symbol_absolute: false,
                symbol_weak: false,
                symbol_version: None,
                symbol_version_unknown: false,
            },
            ElfRelocation {
                offset: 0x1018,
                addend: Some(0),
                relocation_type: reloc::R_AARCH64_GLOB_DAT,
                relocation_name: "R_AARCH64_GLOB_DAT".to_owned(),
                symbol_index: 2,
                symbol_name: Some("packaged_global".to_owned()),
                symbol_value: None,
                symbol_defined: false,
                symbol_absolute: false,
                symbol_weak: false,
                symbol_version: None,
                symbol_version_unknown: false,
            },
            ElfRelocation {
                offset: 0x1020,
                addend: Some(0),
                relocation_type: reloc::R_AARCH64_JUMP_SLOT,
                relocation_name: "R_AARCH64_JUMP_SLOT".to_owned(),
                symbol_index: 3,
                symbol_name: Some("packaged_function".to_owned()),
                symbol_value: None,
                symbol_defined: false,
                symbol_absolute: false,
                symbol_weak: false,
                symbol_version: None,
                symbol_version_unknown: false,
            },
        ];
        let symbols = BTreeMap::from([
            ("packaged_data".to_owned(), 0x1111),
            ("packaged_global".to_owned(), 0x2222),
            ("packaged_function".to_owned(), 0x3333),
        ]);
        let mut image = map_load_image(&[0x5a; 0x100], &plan, 0x1000).unwrap();

        image
            .apply_relocations(&plan, &relocations, &symbols)
            .unwrap();

        for (offset, expected) in [(0x10, 0x1119), (0x18, 0x2222), (0x20, 0x3333)] {
            assert_eq!(
                u64::from_le_bytes(
                    image.bytes().unwrap()[offset..offset + 8]
                        .try_into()
                        .unwrap()
                ),
                expected
            );
        }
        assert_eq!(image.symbol_relocations_applied, 3);
        assert!(image.unresolved_relocations.is_empty());
    }

    #[test]
    fn resolves_versioned_symbols_only_against_the_requested_version() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0,
            image_end: ELF_PAGE_SIZE,
            image_size: ELF_PAGE_SIZE,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0,
                file_size: 0x40,
                memory_size: 0x40,
                alignment: 1,
                mapped_start: 0,
                mapped_end: ELF_PAGE_SIZE,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let requested = ElfSymbolVersion {
            name: "LIB_2".to_owned(),
            hash: 0x1234,
            hidden: false,
        };
        let relocation = ElfRelocation {
            offset: 8,
            addend: Some(0),
            relocation_type: reloc::R_AARCH64_GLOB_DAT,
            relocation_name: "R_AARCH64_GLOB_DAT".to_owned(),
            symbol_index: 1,
            symbol_name: Some("versioned_api".to_owned()),
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: false,
            symbol_version: Some(requested.clone()),
            symbol_version_unknown: false,
        };
        let symbols =
            BTreeMap::from([(symbol_lookup_key("versioned_api", Some(&requested)), 0x5678)]);
        let mut image = map_load_image(&[0; 0x40], &plan, ELF_PAGE_SIZE).unwrap();
        image
            .apply_relocations(&plan, &[relocation.clone()], &symbols)
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(image.bytes().unwrap()[8..16].try_into().unwrap()),
            0x5678
        );

        let mismatched = BTreeMap::from([(
            symbol_lookup_key(
                "versioned_api",
                Some(&ElfSymbolVersion {
                    name: "LIB_1".to_owned(),
                    hash: 0x4321,
                    hidden: false,
                }),
            ),
            0x9999,
        )]);
        let mut image = map_load_image(&[0; 0x40], &plan, ELF_PAGE_SIZE).unwrap();
        image
            .apply_relocations(&plan, &[relocation], &mismatched)
            .unwrap();
        assert_eq!(image.symbol_relocations_applied, 0);
        assert_eq!(image.unresolved_relocations, vec!["versioned_api@LIB_2"]);
    }

    #[test]
    fn keeps_imports_pending_when_elf_version_metadata_is_unavailable() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0,
            image_end: ELF_PAGE_SIZE,
            image_size: ELF_PAGE_SIZE,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0,
                file_size: 0x40,
                memory_size: 0x40,
                alignment: 1,
                mapped_start: 0,
                mapped_end: ELF_PAGE_SIZE,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let relocation = ElfRelocation {
            offset: 8,
            addend: Some(0),
            relocation_type: reloc::R_AARCH64_GLOB_DAT,
            relocation_name: "R_AARCH64_GLOB_DAT".to_owned(),
            symbol_index: 1,
            symbol_name: Some("versioned_api".to_owned()),
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: true,
            symbol_version: None,
            symbol_version_unknown: true,
        };
        let mut image = map_load_image(&[0; 0x40], &plan, ELF_PAGE_SIZE).unwrap();
        image
            .apply_relocations(
                &plan,
                &[relocation],
                &BTreeMap::from([("versioned_api".to_owned(), 0x5678)]),
            )
            .unwrap();

        assert_eq!(image.symbol_relocations_applied, 0);
        assert_eq!(
            image.unresolved_relocations,
            vec!["versioned_api@<versão ELF não decodificada>"]
        );
    }

    #[test]
    fn applies_arm64_16_32_and_pc_relative_relocations_with_checked_widths() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0x1000,
            image_end: 0x2000,
            image_size: 0x1000,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0x1000,
                file_size: 0x100,
                memory_size: 0x100,
                alignment: 1,
                mapped_start: 0x1000,
                mapped_end: 0x2000,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let mut image = map_load_image(&[0; 0x100], &plan, 0x1000).unwrap();
        let bias = image.load_bias;
        let relocation = |offset, kind, name: &str, symbol: &str| ElfRelocation {
            offset,
            addend: Some(0),
            relocation_type: kind,
            relocation_name: name.to_owned(),
            symbol_index: 1,
            symbol_name: Some(symbol.to_owned()),
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: false,
            symbol_version: None,
            symbol_version_unknown: false,
        };
        let relocations = [
            relocation(0x1010, reloc::R_AARCH64_ABS16, "ABS16", "abs16"),
            relocation(0x1012, reloc::R_AARCH64_ABS32, "ABS32", "abs32"),
            relocation(0x1016, reloc::R_AARCH64_PREL16, "PREL16", "prel16"),
            relocation(0x1018, reloc::R_AARCH64_PREL32, "PREL32", "prel32"),
            relocation(0x101c, reloc::R_AARCH64_PREL64, "PREL64", "prel64"),
        ];
        let symbols = BTreeMap::from([
            ("abs16".to_owned(), 0x1234),
            ("abs32".to_owned(), 0x1234_5678),
            ("prel16".to_owned(), bias + 0x1100),
            ("prel32".to_owned(), bias + 0x0f00),
            ("prel64".to_owned(), bias + 0x1000),
        ]);

        image
            .apply_relocations(&plan, &relocations, &symbols)
            .unwrap();

        assert_eq!(
            u16::from_le_bytes(image.bytes().unwrap()[0x10..0x12].try_into().unwrap()),
            0x1234
        );
        assert_eq!(
            u32::from_le_bytes(image.bytes().unwrap()[0x12..0x16].try_into().unwrap()),
            0x1234_5678
        );
        assert_eq!(
            i16::from_le_bytes(image.bytes().unwrap()[0x16..0x18].try_into().unwrap()),
            0xea
        );
        assert_eq!(
            i32::from_le_bytes(image.bytes().unwrap()[0x18..0x1c].try_into().unwrap()),
            -0x118
        );
        assert_eq!(
            i64::from_le_bytes(image.bytes().unwrap()[0x1c..0x24].try_into().unwrap()),
            -0x1c
        );
        assert_eq!(image.symbol_relocations_applied, 5);
    }

    #[test]
    fn rejects_relocation_overflow_without_partially_writing_image() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0,
            image_end: ELF_PAGE_SIZE,
            image_size: ELF_PAGE_SIZE,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0,
                file_size: 0x40,
                memory_size: 0x40,
                alignment: 1,
                mapped_start: 0,
                mapped_end: ELF_PAGE_SIZE,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let valid = ElfRelocation {
            offset: 8,
            addend: Some(0),
            relocation_type: reloc::R_AARCH64_ABS32,
            relocation_name: "R_AARCH64_ABS32".to_owned(),
            symbol_index: 1,
            symbol_name: Some("small_symbol".to_owned()),
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: false,
            symbol_version: None,
            symbol_version_unknown: false,
        };
        let overflow = ElfRelocation {
            offset: 16,
            relocation_type: reloc::R_AARCH64_PREL16,
            relocation_name: "R_AARCH64_PREL16".to_owned(),
            symbol_name: Some("far_symbol".to_owned()),
            ..valid.clone()
        };
        let mut image = map_load_image(&[0xab; 0x40], &plan, ELF_PAGE_SIZE).unwrap();
        let before = image.bytes().unwrap().to_vec();
        let far_symbol = image.load_bias + 0x1_0000;

        assert!(
            image
                .apply_relocations(
                    &plan,
                    &[valid, overflow],
                    &BTreeMap::from([
                        ("small_symbol".to_owned(), 0x1234),
                        ("far_symbol".to_owned(), far_symbol),
                    ]),
                )
                .is_err()
        );
        assert_eq!(image.bytes().unwrap(), before);
        assert_eq!(image.symbol_relocations_applied, 0);
    }

    #[test]
    fn weak_missing_symbols_resolve_to_zero_but_strong_imports_remain_unresolved() {
        let plan = ElfLoadPlan {
            page_size: ELF_PAGE_SIZE,
            image_start: 0,
            image_end: ELF_PAGE_SIZE,
            image_size: ELF_PAGE_SIZE,
            segments: vec![ElfLoadSegment {
                file_offset: 0,
                virtual_address: 0,
                file_size: 0x40,
                memory_size: 0x40,
                alignment: 1,
                mapped_start: 0,
                mapped_end: ELF_PAGE_SIZE,
                readable: true,
                writable: true,
                executable: false,
            }],
        };
        let weak = ElfRelocation {
            offset: 8,
            addend: Some(0),
            relocation_type: reloc::R_AARCH64_GLOB_DAT,
            relocation_name: "R_AARCH64_GLOB_DAT".to_owned(),
            symbol_index: 1,
            symbol_name: Some("optional_api".to_owned()),
            symbol_value: None,
            symbol_defined: false,
            symbol_absolute: false,
            symbol_weak: true,
            symbol_version: None,
            symbol_version_unknown: false,
        };
        let strong = ElfRelocation {
            offset: 16,
            symbol_name: Some("android_api_not_provided".to_owned()),
            symbol_weak: false,
            ..weak.clone()
        };
        let mut image = map_load_image(&[0; 0x40], &plan, ELF_PAGE_SIZE).unwrap();

        image
            .apply_relocations(&plan, &[weak, strong], &BTreeMap::new())
            .unwrap();

        assert_eq!(
            u64::from_le_bytes(image.bytes().unwrap()[8..16].try_into().unwrap()),
            0
        );
        assert_eq!(image.symbol_relocations_applied, 1);
        assert_eq!(
            image.unresolved_relocations,
            vec!["android_api_not_provided".to_owned()]
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
