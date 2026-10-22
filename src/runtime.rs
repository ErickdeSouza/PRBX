use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use zip::ZipArchive;

use crate::apk;

const TARGET_ABI: &str = "arm64-v8a";
const MAX_LIBRARY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_LIBRARY_SIZE: u64 = 1024 * 1024 * 1024;

pub struct PreparedApp {
    pub package: String,
    pub app_root: PathBuf,
    pub apk_path: PathBuf,
    pub native_libraries: usize,
    pub shared_storage: PathBuf,
}

pub fn default_data_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(local_app_data).join("PRBX").join("apps"));
        }
    }

    if let Some(xdg_data_home) = env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg_data_home).join("prbx").join("apps"));
    }
    if let Some(home) = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        return Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("prbx")
            .join("apps"));
    }

    bail!("não foi possível localizar o diretório de dados do usuário; informe --data-dir");
}

pub fn prepare(apk_path: &Path, data_dir: &Path) -> Result<PreparedApp> {
    let report = apk::inspect(apk_path)
        .with_context(|| format!("não foi possível validar o APK {}", apk_path.display()))?;
    let manifest = report
        .manifest
        .as_ref()
        .context("o APK não contém AndroidManifest.xml")?
        .as_ref()
        .map_err(|error| anyhow::anyhow!("não foi possível ler o manifesto: {error}"))?;
    let package = manifest
        .package
        .as_deref()
        .context("o manifesto não informa o nome do pacote")?;
    validate_package_name(package)?;

    if !report
        .libraries
        .iter()
        .any(|library| library.abi == TARGET_ABI)
    {
        bail!("o APK não contém bibliotecas para a ABI {TARGET_ABI}");
    }

    let app_root = data_dir.join(package);
    let install_dir = app_root.join("install");
    let native_dir = install_dir.join("native").join(TARGET_ABI);
    let apk_dir = install_dir.join("apk");
    let shared_storage = app_root.join("storage");
    let stored_apk = apk_dir.join("base.apk");

    fs::create_dir_all(&native_dir)
        .with_context(|| format!("não foi possível criar {}", native_dir.display()))?;
    fs::create_dir_all(&apk_dir)
        .with_context(|| format!("não foi possível criar {}", apk_dir.display()))?;
    fs::create_dir_all(app_root.join("data"))?;
    fs::create_dir_all(app_root.join("cache"))?;
    fs::create_dir_all(app_root.join("files"))?;
    fs::create_dir_all(shared_storage.join("Delta"))?;

    fs::copy(apk_path, &stored_apk).with_context(|| {
        format!(
            "não foi possível copiar o APK para {}",
            stored_apk.display()
        )
    })?;

    let file = File::open(apk_path)
        .with_context(|| format!("não foi possível abrir {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file).context("o APK não é um arquivo ZIP válido")?;
    let mut seen_libraries = BTreeSet::new();
    let mut total_size = 0_u64;
    let mut native_libraries = 0;

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .with_context(|| format!("não foi possível ler a entrada ZIP {index}"))?;
        let Some(file_name) = library_file_name(entry.name(), TARGET_ABI).map(str::to_owned) else {
            continue;
        };
        if !seen_libraries.insert(file_name.clone()) {
            bail!("o APK contém a biblioteca duplicada {file_name}");
        }
        if entry.size() > MAX_LIBRARY_SIZE {
            bail!("{file_name} excede o limite de {MAX_LIBRARY_SIZE} bytes");
        }
        total_size = total_size
            .checked_add(entry.size())
            .context("overflow no tamanho total das bibliotecas")?;
        if total_size > MAX_TOTAL_LIBRARY_SIZE {
            bail!("as bibliotecas excedem o limite total de {MAX_TOTAL_LIBRARY_SIZE} bytes");
        }

        let destination = native_dir.join(&file_name);
        let mut output = File::create(&destination)
            .with_context(|| format!("não foi possível criar {}", destination.display()))?;
        let expected_size = entry.size();
        let copied = io::copy(
            &mut entry.take(expected_size.saturating_add(1)),
            &mut output,
        )
        .with_context(|| format!("falha ao extrair {file_name}"))?;
        if copied != expected_size {
            bail!("tamanho extraído inesperado para {file_name}");
        }
        native_libraries += 1;
    }

    if native_libraries == 0 {
        bail!("não foi possível extrair bibliotecas para a ABI {TARGET_ABI}");
    }

    Ok(PreparedApp {
        package: package.to_owned(),
        app_root,
        apk_path: stored_apk,
        native_libraries,
        shared_storage,
    })
}

pub fn map_android_path(app_root: &Path, android_path: &str) -> Result<PathBuf> {
    const SHARED_STORAGE: &str = "/storage/emulated/0";
    const PRIVATE_DATA: &str = "/data/data";

    let app_package = app_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("o diretório do app não contém um nome de pacote válido")?;
    let (base, relative) = if android_path == SHARED_STORAGE {
        (app_root.join("storage"), "")
    } else if let Some(relative) = android_path.strip_prefix("/storage/emulated/0/") {
        (app_root.join("storage"), relative)
    } else if android_path == PRIVATE_DATA {
        (app_root.join("data"), "")
    } else if let Some(relative) = android_path.strip_prefix("/data/data/") {
        let (package, package_relative) = relative.split_once('/').unwrap_or((relative, ""));
        if package != app_package {
            bail!("caminho privado pertence a outro pacote Android: {android_path}");
        }
        (app_root.join("data"), package_relative)
    } else {
        bail!("caminho Android não mapeado: {android_path}");
    };

    if relative.split('/').any(|component| component == "..") {
        bail!("caminho Android contém componente de travessia: {android_path}");
    }

    let mut mapped = base;
    for component in relative
        .split('/')
        .filter(|component| !component.is_empty())
    {
        if component == "." || component.contains('\\') {
            bail!("caminho Android inválido: {android_path}");
        }
        mapped.push(component);
    }
    Ok(mapped)
}

fn library_file_name<'a>(path: &'a str, abi: &str) -> Option<&'a str> {
    let mut components = path.split('/');
    if components.next()? != "lib" || components.next()? != abi {
        return None;
    }
    let file_name = components.next()?;
    if components.next().is_some()
        || !file_name.starts_with("lib")
        || !file_name.ends_with(".so")
        || file_name.contains('\\')
        || file_name == "lib.so"
    {
        return None;
    }
    Some(file_name)
}

fn validate_package_name(package: &str) -> Result<()> {
    if package.is_empty()
        || package.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    {
        bail!("nome de pacote Android inválido: {package}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_shared_storage_and_private_data() {
        let root = Path::new("/home/test/.local/share/prbx/apps/com.example");
        assert_eq!(
            map_android_path(root, "/storage/emulated/0/Delta").unwrap(),
            root.join("storage").join("Delta")
        );
        assert_eq!(
            map_android_path(root, "/data/data/com.example/files").unwrap(),
            root.join("data").join("files")
        );
    }

    #[test]
    fn rejects_unmapped_and_traversal_paths() {
        let root = Path::new("/tmp/prbx");
        assert!(map_android_path(root, "/etc/passwd").is_err());
        assert!(map_android_path(root, "/storage/emulated/0/../secret").is_err());
        assert!(map_android_path(root, "/storage/emulated/0\\..\\secret").is_err());
        assert!(map_android_path(root, "/data/data/com.other/files").is_err());
    }

    #[test]
    fn accepts_only_flat_shared_object_paths_for_target_abi() {
        assert_eq!(
            library_file_name("lib/arm64-v8a/libroblox.so", TARGET_ABI),
            Some("libroblox.so")
        );
        assert_eq!(
            library_file_name("lib/x86_64/libroblox.so", TARGET_ABI),
            None
        );
        assert_eq!(
            library_file_name("lib/arm64-v8a/nested/libroblox.so", TARGET_ABI),
            None
        );
        assert_eq!(
            library_file_name("lib/arm64-v8a/../../outside.so", TARGET_ABI),
            None
        );
    }

    #[test]
    fn rejects_invalid_package_names() {
        assert!(validate_package_name("com.roblox.client").is_ok());
        assert!(validate_package_name("../outside").is_err());
        assert!(validate_package_name("com..client").is_err());
    }
}
