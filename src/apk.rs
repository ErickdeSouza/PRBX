use std::collections::{BTreeMap, BTreeSet};
use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result};
use zip::ZipArchive;

use crate::{
    analysis::{dex, manifest},
    elf,
};

const MAX_LIBRARY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_DEX_SIZE: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;

pub struct ApkReport {
    pub manifest_size: Option<u64>,
    pub dex_files: Vec<String>,
    pub manifest: Option<std::result::Result<manifest::ManifestReport, String>>,
    pub native_methods: Vec<dex::NativeMethod>,
    pub dex_errors: Vec<(String, String)>,
    pub framework_calls: BTreeMap<String, usize>,
    pub framework_call_sites: usize,
    pub framework_classes: BTreeSet<String>,
    pub library_loads: Vec<dex::LibraryLoad>,
    pub libraries: Vec<NativeLibrary>,
}

pub struct NativeLibrary {
    pub path: String,
    pub abi: String,
    pub size: u64,
    pub compressed_size: u64,
    pub elf: std::result::Result<elf::ElfReport, String>,
}

pub fn inspect(path: &Path) -> Result<ApkReport> {
    let file =
        File::open(path).with_context(|| format!("não foi possível abrir {}", path.display()))?;
    let mut archive = ZipArchive::new(file).with_context(|| {
        format!(
            "{} não parece ser um APK/arquivo ZIP válido",
            path.display()
        )
    })?;

    let mut manifest_size = None;
    let mut manifest_index = None;
    let mut dex_files = Vec::new();
    let mut dex_entries = Vec::new();
    let mut library_entries = Vec::new();

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .with_context(|| format!("não foi possível ler a entrada ZIP de índice {index}"))?;
        let name = entry.name().to_owned();
        if entry.is_dir() {
            continue;
        }
        if name == "AndroidManifest.xml" {
            manifest_size = Some(entry.size());
            manifest_index = Some(index);
        }
        if is_dex_file(&name) {
            dex_files.push(name.clone());
            dex_entries.push((index, name.clone(), entry.size()));
        }
        if let Some(abi) = abi_from_path(&name) {
            let abi = abi.to_owned();
            library_entries.push((index, name, abi));
        }
    }

    dex_files.sort();
    let manifest = if let Some(index) = manifest_index {
        let mut entry = archive
            .by_index(index)
            .context("não foi possível reler AndroidManifest.xml")?;
        if entry.size() > MAX_MANIFEST_SIZE {
            Some(Err(format!(
                "manifesto excede o limite de análise de {MAX_MANIFEST_SIZE} bytes"
            )))
        } else {
            let bytes = read_limited(&mut entry, MAX_MANIFEST_SIZE)
                .context("falha ao descomprimir AndroidManifest.xml")?;
            Some(manifest::parse(&bytes).map_err(|error| format!("{error:#}")))
        }
    } else {
        None
    };

    let mut native_methods = Vec::new();
    let mut dex_errors = Vec::new();
    let mut framework_calls = BTreeMap::new();
    let mut framework_call_sites = 0;
    let mut framework_classes = BTreeSet::new();
    let mut library_loads = Vec::new();
    for (index, name, size) in dex_entries {
        if size > MAX_DEX_SIZE {
            dex_errors.push((
                name,
                format!("arquivo excede o limite de análise de {MAX_DEX_SIZE} bytes"),
            ));
            continue;
        }
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("não foi possível ler a entrada {name}"))?;
        let bytes = read_limited(&mut entry, MAX_DEX_SIZE)
            .with_context(|| format!("falha ao descomprimir {name}"))?;
        match dex::parse(&bytes, &name) {
            Ok(report) => {
                native_methods.extend(report.native_methods);
                framework_call_sites += report.framework_call_sites;
                framework_classes.extend(report.framework_classes);
                for (method, count) in report.framework_calls {
                    *framework_calls.entry(method).or_insert(0) += count;
                }
                library_loads.extend(report.library_loads);
            }
            Err(error) => dex_errors.push((name, format!("{error:#}"))),
        }
    }

    let mut libraries = Vec::with_capacity(library_entries.len());
    for (index, name, abi) in library_entries {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("não foi possível ler a entrada {name}"))?;
        let size = entry.size();
        let compressed_size = entry.compressed_size();
        let analysis = if size > MAX_LIBRARY_SIZE {
            Err(format!(
                "arquivo excede o limite de análise de {MAX_LIBRARY_SIZE} bytes"
            ))
        } else {
            let bytes = read_limited(&mut entry, MAX_LIBRARY_SIZE)
                .with_context(|| format!("falha ao descomprimir {name}"))?;
            elf::analyze(&bytes, &abi).map_err(|error| format!("{error:#}"))
        };

        libraries.push(NativeLibrary {
            path: name,
            abi,
            size,
            compressed_size,
            elf: analysis,
        });
    }

    Ok(ApkReport {
        manifest_size,
        dex_files,
        manifest,
        native_methods,
        dex_errors,
        framework_calls,
        framework_call_sites,
        framework_classes,
        library_loads,
        libraries,
    })
}

fn read_limited(reader: &mut impl Read, limit: u64) -> Result<Vec<u8>> {
    let capacity = usize::try_from(limit.min(usize::MAX as u64))
        .context("limite de leitura excede a capacidade do sistema")?;
    let mut bytes = Vec::with_capacity(capacity.min(16 * 1024 * 1024));
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        anyhow::bail!("entrada descompactada excede o limite de {limit} bytes");
    }
    Ok(bytes)
}

fn abi_from_path(name: &str) -> Option<&str> {
    let mut components = name.split('/');
    if components.next()? != "lib" {
        return None;
    }
    let abi = components.next()?;
    let file_name = components.next()?;
    if components.next().is_some() || !file_name.starts_with("lib") || !file_name.ends_with(".so") {
        return None;
    }
    Some(abi)
}

fn is_dex_file(name: &str) -> bool {
    if name == "classes.dex" {
        return true;
    }
    let Some(number) = name
        .strip_prefix("classes")
        .and_then(|name| name.strip_suffix(".dex"))
    else {
        return false;
    };
    !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn recognizes_only_expected_library_paths() {
        assert_eq!(
            abi_from_path("lib/arm64-v8a/libroblox.so"),
            Some("arm64-v8a")
        );
        assert_eq!(abi_from_path("assets/libroblox.so"), None);
        assert_eq!(abi_from_path("lib/arm64-v8a/nested/libx.so"), None);
        assert_eq!(abi_from_path("lib/arm64-v8a/readme.txt"), None);
    }

    #[test]
    fn recognizes_primary_and_multidex_files() {
        assert!(is_dex_file("classes.dex"));
        assert!(is_dex_file("classes2.dex"));
        assert!(!is_dex_file("classes.dex.backup"));
        assert!(!is_dex_file("classesx.dex"));
    }

    #[test]
    fn reads_entry_with_a_hard_decompressed_size_limit() {
        let mut accepted = Cursor::new(b"small".to_vec());
        assert_eq!(read_limited(&mut accepted, 5).unwrap(), b"small");

        let mut oversized = Cursor::new(b"too large".to_vec());
        assert!(read_limited(&mut oversized, 4).is_err());
    }
}
