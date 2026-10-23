use anyhow::{Context, Result};
use goblin::elf::{Elf, header};
use std::collections::BTreeMap;

pub struct ElfReport {
    pub class: &'static str,
    pub machine: &'static str,
    pub abi_matches: bool,
    pub needed: Vec<String>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub android_api_imports: BTreeMap<&'static str, usize>,
}

pub fn analyze(bytes: &[u8], abi: &str) -> Result<ElfReport> {
    let elf = Elf::parse(bytes).context("arquivo não é um ELF válido")?;
    let machine = machine_name(elf.header.e_machine);
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
        abi_matches: abi_matches_machine(abi, elf.header.e_machine),
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
