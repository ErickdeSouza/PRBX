use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};
use zip::ZipArchive;

use crate::apk;

const TARGET_ABI: &str = "arm64-v8a";
const MAX_LIBRARY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_LIBRARY_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_ASSET_SIZE: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_ASSET_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ASSET_COUNT: usize = 100_000;
static STAGING_ID: AtomicU64 = AtomicU64::new(0);

struct StagingDirectory(PathBuf);

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "Aviso: não foi possível limpar o staging {}: {error}",
                self.0.display()
            );
        }
    }
}

pub struct PreparedApp {
    pub package: String,
    pub app_root: PathBuf,
    pub apk_path: PathBuf,
    pub native_libraries: usize,
    pub assets: usize,
    pub asset_bytes: u64,
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
    fs::create_dir_all(&app_root)
        .with_context(|| format!("não foi possível criar {}", app_root.display()))?;
    let staging = create_staging_directory(&app_root)?;
    let staged_install = staging.0.join("install");
    let native_dir = staged_install.join("native").join(TARGET_ABI);
    let apk_dir = staged_install.join("apk");
    let shared_storage = app_root.join("storage");
    let staged_apk = apk_dir.join("base.apk");
    let stored_apk = install_dir.join("apk").join("base.apk");

    fs::create_dir_all(&native_dir)
        .with_context(|| format!("não foi possível criar {}", native_dir.display()))?;
    fs::create_dir_all(&apk_dir)
        .with_context(|| format!("não foi possível criar {}", apk_dir.display()))?;
    fs::copy(apk_path, &staged_apk).with_context(|| {
        format!(
            "não foi possível copiar o APK para {}",
            staged_apk.display()
        )
    })?;

    let file = File::open(apk_path)
        .with_context(|| format!("não foi possível abrir {}", apk_path.display()))?;
    let mut archive = ZipArchive::new(file).context("o APK não é um arquivo ZIP válido")?;
    let mut seen_libraries = BTreeSet::new();
    let mut seen_assets = BTreeSet::new();
    let mut total_size = 0_u64;
    let mut native_libraries = 0;
    let mut asset_bytes = 0_u64;
    let mut assets = 0;

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .with_context(|| format!("não foi possível ler a entrada ZIP {index}"))?;
        if let Some(file_name) = library_file_name(entry.name(), TARGET_ABI).map(str::to_owned) {
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
            extract_entry(entry, &native_dir.join(&file_name), &file_name)?;
            native_libraries += 1;
            continue;
        }

        if entry.is_dir() {
            continue;
        }
        let Some(relative_path) = asset_relative_path(entry.name())? else {
            continue;
        };
        let asset_key = relative_path.to_string_lossy().to_lowercase();
        if !seen_assets.insert(asset_key) {
            bail!(
                "o APK contém um caminho de asset duplicado: {}",
                entry.name()
            );
        }
        if assets >= MAX_ASSET_COUNT {
            bail!("o APK excede o limite de {MAX_ASSET_COUNT} arquivos em assets/");
        }
        if entry.size() > MAX_ASSET_SIZE {
            bail!(
                "asset {} excede o limite de {MAX_ASSET_SIZE} bytes",
                entry.name()
            );
        }
        asset_bytes = asset_bytes
            .checked_add(entry.size())
            .context("overflow no tamanho total dos assets")?;
        if asset_bytes > MAX_TOTAL_ASSET_SIZE {
            bail!("os assets excedem o limite total de {MAX_TOTAL_ASSET_SIZE} bytes");
        }
        let destination = staged_install.join("assets").join(&relative_path);
        extract_entry(entry, &destination, &relative_path.display().to_string())?;
        assets += 1;
    }

    if native_libraries == 0 {
        bail!("não foi possível extrair bibliotecas para a ABI {TARGET_ABI}");
    }

    fs::create_dir_all(app_root.join("data"))?;
    fs::create_dir_all(app_root.join("cache"))?;
    fs::create_dir_all(app_root.join("files"))?;
    fs::create_dir_all(shared_storage.join("Delta"))?;
    replace_install(&staged_install, &install_dir)?;

    Ok(PreparedApp {
        package: package.to_owned(),
        app_root,
        apk_path: stored_apk,
        native_libraries,
        assets,
        asset_bytes,
        shared_storage,
    })
}

fn create_staging_directory(app_root: &Path) -> Result<StagingDirectory> {
    for _ in 0..100 {
        let id = STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let path = app_root.join(format!(".install-staging-{}-{id}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(StagingDirectory(path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("não foi possível criar staging {}", path.display()));
            }
        }
    }
    bail!("não foi possível reservar um diretório staging exclusivo")
}

fn replace_install(staged_install: &Path, install_dir: &Path) -> Result<()> {
    let backup = unique_sibling_path(install_dir, "install-backup")?;
    let had_previous_install = match fs::symlink_metadata(install_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::rename(install_dir, &backup).with_context(|| {
                format!(
                    "não foi possível guardar a instalação atual em {}",
                    backup.display()
                )
            })?;
            true
        }
        Ok(_) => bail!(
            "o caminho da instalação existe, mas não é um diretório real: {}",
            install_dir.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "não foi possível verificar a instalação atual {}",
                    install_dir.display()
                )
            });
        }
    };

    if let Err(error) = fs::rename(staged_install, install_dir) {
        if had_previous_install {
            fs::rename(&backup, install_dir).with_context(|| {
                format!(
                    "falha ao instalar a nova versão ({error}) e ao restaurar {}",
                    backup.display()
                )
            })?;
        }
        return Err(error).with_context(|| {
            format!(
                "não foi possível ativar a nova instalação em {}",
                install_dir.display()
            )
        });
    }

    if had_previous_install {
        fs::remove_dir_all(&backup)
            .with_context(|| format!("não foi possível remover backup {}", backup.display()))?;
    }
    Ok(())
}

fn unique_sibling_path(path: &Path, label: &str) -> Result<PathBuf> {
    let parent = path
        .parent()
        .context("o caminho da instalação não possui diretório pai")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("o caminho da instalação não possui nome válido")?;
    for _ in 0..100 {
        let id = STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{name}-{label}-{}-{id}", std::process::id()));
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("não foi possível verificar {}", candidate.display())
                });
            }
        }
    }
    bail!("não foi possível reservar um caminho temporário exclusivo")
}

fn extract_entry(
    mut entry: zip::read::ZipFile<'_, File>,
    destination: &Path,
    description: &str,
) -> Result<()> {
    let expected_size = entry.size();
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("não foi possível criar {}", parent.display()))?;
    }
    let mut output = File::create(destination)
        .with_context(|| format!("não foi possível criar {}", destination.display()))?;
    let copied = io::copy(
        &mut entry.by_ref().take(expected_size.saturating_add(1)),
        &mut output,
    )
    .with_context(|| format!("falha ao extrair {description}"))?;
    if copied != expected_size {
        bail!("tamanho extraído inesperado para {description}");
    }
    Ok(())
}

fn asset_relative_path(path: &str) -> Result<Option<PathBuf>> {
    let Some(relative) = path.strip_prefix("assets/") else {
        return Ok(None);
    };
    if relative.is_empty() {
        bail!("entrada de asset sem nome de arquivo");
    }

    let mut result = PathBuf::new();
    for component in relative.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('\\')
            || component.contains(':')
        {
            bail!("caminho de asset inválido no APK: {path}");
        }
        result.push(component);
    }
    Ok(Some(result))
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
    fn accepts_nested_assets_and_rejects_unsafe_asset_paths() {
        assert_eq!(
            asset_relative_path("assets/ExtraContent/LuaPackages/init.lua").unwrap(),
            Some(PathBuf::from("ExtraContent/LuaPackages/init.lua"))
        );
        assert_eq!(asset_relative_path("res/raw/data.bin").unwrap(), None);
        assert!(asset_relative_path("assets/../outside").is_err());
        assert!(asset_relative_path("assets\\outside").is_ok_and(|path| path.is_none()));
        assert!(asset_relative_path("assets/folder\\..\\outside").is_err());
        assert!(asset_relative_path("assets/C:/outside").is_err());
        assert!(asset_relative_path("assets/folder//file").is_err());
    }

    #[test]
    fn rejects_invalid_package_names() {
        assert!(validate_package_name("com.roblox.client").is_ok());
        assert!(validate_package_name("../outside").is_err());
        assert!(validate_package_name("com..client").is_err());
    }

    #[test]
    fn install_replacement_removes_stale_files_and_preserves_app_data() {
        let root = create_staging_directory(&env::temp_dir()).unwrap();
        let install_dir = root.0.join("install");
        let old_asset = install_dir.join("assets/old.txt");
        fs::create_dir_all(old_asset.parent().unwrap()).unwrap();
        fs::write(&old_asset, "old").unwrap();
        fs::create_dir_all(root.0.join("data")).unwrap();
        fs::write(root.0.join("data/save.dat"), "save").unwrap();

        let staging = create_staging_directory(&root.0).unwrap();
        let staged_install = staging.0.join("install");
        let new_asset = staged_install.join("assets/new.txt");
        fs::create_dir_all(new_asset.parent().unwrap()).unwrap();
        fs::write(&new_asset, "new").unwrap();

        replace_install(&staged_install, &install_dir).unwrap();

        assert!(!old_asset.exists());
        assert_eq!(
            fs::read(&install_dir.join("assets/new.txt")).unwrap(),
            b"new"
        );
        assert_eq!(fs::read(root.0.join("data/save.dat")).unwrap(), b"save");
    }

    #[test]
    fn failed_install_replacement_restores_previous_install() {
        let root = create_staging_directory(&env::temp_dir()).unwrap();
        let install_dir = root.0.join("install");
        fs::create_dir(&install_dir).unwrap();
        fs::write(install_dir.join("previous.txt"), "previous").unwrap();

        assert!(replace_install(&root.0.join("missing/install"), &install_dir).is_err());
        assert_eq!(
            fs::read(install_dir.join("previous.txt")).unwrap(),
            b"previous"
        );
    }
}
