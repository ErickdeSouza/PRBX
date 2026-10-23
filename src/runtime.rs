use std::{
    collections::{BTreeMap, BTreeSet},
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
    pub dependency_report: PathBuf,
    pub packaged_dependencies: usize,
    pub android_dependencies: usize,
    pub unknown_dependencies: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DependencyKind {
    Packaged,
    AndroidPlatform,
    Unknown,
}

struct NativeDependency {
    library: String,
    dependency: String,
    kind: DependencyKind,
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

    let target_libraries = report
        .libraries
        .iter()
        .filter(|library| library.abi == TARGET_ABI)
        .collect::<Vec<_>>();
    if target_libraries.is_empty() {
        bail!("o APK não contém bibliotecas para a ABI {TARGET_ABI}");
    }
    for library in &target_libraries {
        let elf = library.elf.as_ref().map_err(|error| {
            anyhow::anyhow!(
                "não foi possível validar a biblioteca {}: {error}",
                library.path
            )
        })?;
        if !elf.abi_matches {
            bail!(
                "a arquitetura ELF de {} não corresponde à ABI {TARGET_ABI}",
                library.path
            );
        }
    }
    let dependencies = native_dependencies(&target_libraries)?;
    let dependency_report = format!("native-dependencies-{TARGET_ABI}.txt");
    let packaged_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.kind == DependencyKind::Packaged)
        .count();
    let android_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.kind == DependencyKind::AndroidPlatform)
        .count();
    let unknown_dependencies = dependencies
        .iter()
        .filter(|dependency| dependency.kind == DependencyKind::Unknown)
        .count();

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
    write_dependency_report(&staged_install.join(&dependency_report), &dependencies)?;

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
    fs::create_dir_all(app_root.join("data_de"))?;
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
        dependency_report: install_dir.join(&dependency_report),
        packaged_dependencies,
        android_dependencies,
        unknown_dependencies,
    })
}

fn native_dependencies(libraries: &[&crate::apk::NativeLibrary]) -> Result<Vec<NativeDependency>> {
    let mut packaged = BTreeSet::new();
    for library in libraries {
        let file_name = Path::new(&library.path)
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("caminho de biblioteca inválido: {}", library.path))?;
        packaged.insert(file_name.to_owned());
    }

    let mut dependencies = BTreeMap::new();
    for library in libraries {
        let file_name = Path::new(&library.path)
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("caminho de biblioteca inválido: {}", library.path))?;
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        for dependency in &elf.needed {
            let kind = if packaged.contains(dependency) {
                DependencyKind::Packaged
            } else if is_android_platform_library(dependency) {
                DependencyKind::AndroidPlatform
            } else {
                DependencyKind::Unknown
            };
            dependencies
                .entry((file_name.to_owned(), dependency.clone()))
                .or_insert(NativeDependency {
                    library: file_name.to_owned(),
                    dependency: dependency.clone(),
                    kind,
                });
        }
    }
    Ok(dependencies.into_values().collect())
}

fn is_android_platform_library(name: &str) -> bool {
    matches!(
        name,
        "libandroid.so"
            | "libc.so"
            | "libdl.so"
            | "libEGL.so"
            | "libGLESv1_CM.so"
            | "libGLESv2.so"
            | "libGLESv3.so"
            | "libjnigraphics.so"
            | "liblog.so"
            | "libm.so"
            | "libmediandk.so"
            | "libnativewindow.so"
            | "libOpenMAXAL.so"
            | "libOpenSLES.so"
            | "libvulkan.so"
            | "libz.so"
    )
}

fn write_dependency_report(path: &Path, dependencies: &[NativeDependency]) -> Result<()> {
    let mut report = String::from(
        "Dependências ELF observadas estaticamente; isto não confirma disponibilidade em runtime.\n",
    );
    for dependency in dependencies {
        let (status, detail) = match dependency.kind {
            DependencyKind::Packaged => ("NO APK", "biblioteca empacotada"),
            DependencyKind::AndroidPlatform => (
                "PLATAFORMA ANDROID",
                "fornecida pela plataforma; runtime ainda necessário",
            ),
            DependencyKind::Unknown => (
                "NÃO RESOLVIDA",
                "não encontrada no APK nem na lista conhecida",
            ),
        };
        use std::fmt::Write as _;
        writeln!(
            report,
            "{} -> {} | {} ({detail})",
            dependency.library, dependency.dependency, status
        )
        .expect("escrever em String não falha");
    }
    fs::write(path, report)
        .with_context(|| format!("não foi possível gravar o relatório {}", path.display()))
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
    let app_package = app_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("o diretório do app não contém um nome de pacote válido")?;
    if !android_path.starts_with('/') || android_path.contains('\\') || android_path.contains('\0')
    {
        bail!("caminho Android inválido: {android_path}");
    }

    if let Some(relative) = strip_android_prefix(
        android_path,
        &[
            "/storage/emulated/0",
            "/storage/self/primary",
            "/mnt/sdcard",
            "/sdcard",
        ],
    ) {
        let components = validate_android_components(relative, android_path)?;
        validate_external_package_scope(&components, app_package, android_path)?;
        return Ok(append_components(app_root.join("storage"), &components));
    }

    for (prefix, directory) in [
        ("/data/data", "data"),
        ("/data/user/0", "data"),
        ("/data/user_de/0", "data_de"),
    ] {
        if let Some(relative) = strip_android_prefix(android_path, &[prefix]) {
            let components = validate_android_components(relative, android_path)?;
            let Some((package, package_components)) = components.split_first() else {
                bail!("caminho Android privado não especifica o pacote: {android_path}");
            };
            if *package != app_package {
                bail!("caminho privado pertence a outro pacote Android: {android_path}");
            }
            let (base, remaining) = if directory == "data" {
                split_private_data_directory(app_root, package_components)
            } else {
                (app_root.join(directory), package_components)
            };
            return Ok(append_components(base, remaining));
        }
    }

    bail!("caminho Android não mapeado: {android_path}")
}

fn strip_android_prefix<'a>(path: &'a str, prefixes: &[&str]) -> Option<&'a str> {
    prefixes.iter().find_map(|prefix| {
        if path == *prefix {
            Some("")
        } else {
            path.strip_prefix(prefix)
                .and_then(|suffix| suffix.strip_prefix('/'))
        }
    })
}

fn validate_android_components<'a>(relative: &'a str, original: &str) -> Result<Vec<&'a str>> {
    if relative.is_empty() {
        return Ok(Vec::new());
    }
    let components = relative
        .trim_end_matches('/')
        .split('/')
        .collect::<Vec<_>>();
    if components.iter().any(|component| {
        component.is_empty() || *component == "." || *component == ".." || component.contains(':')
    }) {
        bail!("caminho Android contém componente inválido: {original}");
    }
    Ok(components)
}

fn validate_external_package_scope(
    components: &[&str],
    app_package: &str,
    original: &str,
) -> Result<()> {
    if components.len() >= 3
        && components[0] == "Android"
        && matches!(components[1], "data" | "obb" | "media")
        && components[2] != app_package
    {
        bail!("caminho externo pertence a outro pacote Android: {original}");
    }
    Ok(())
}

fn append_components(mut base: PathBuf, components: &[&str]) -> PathBuf {
    for component in components {
        base.push(component);
    }
    base
}

fn split_private_data_directory<'a>(
    app_root: &Path,
    components: &'a [&'a str],
) -> (PathBuf, &'a [&'a str]) {
    match components.split_first() {
        Some((first, remaining)) if *first == "cache" => (app_root.join("cache"), remaining),
        Some((first, remaining)) if *first == "files" => (app_root.join("files"), remaining),
        Some((first, remaining)) if *first == "code_cache" => {
            (app_root.join("cache").join("code_cache"), remaining)
        }
        Some((first, remaining)) if *first == "no_backup" => {
            (app_root.join("data").join("no_backup"), remaining)
        }
        _ => (app_root.join("data"), components),
    }
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
    use crate::elf::ElfReport;
    use std::collections::BTreeMap;

    fn native_library(path: &str, needed: &[&str]) -> crate::apk::NativeLibrary {
        crate::apk::NativeLibrary {
            path: path.to_owned(),
            abi: TARGET_ABI.to_owned(),
            size: 0,
            compressed_size: 0,
            elf: Ok(ElfReport {
                class: "ELF64",
                machine: "AArch64",
                abi_matches: true,
                needed: needed.iter().map(|name| (*name).to_owned()).collect(),
                imports: Vec::new(),
                exports: Vec::new(),
                android_api_imports: BTreeMap::new(),
            }),
        }
    }

    #[test]
    fn maps_shared_storage_and_private_data() {
        let root = Path::new("/home/test/.local/share/prbx/apps/com.example");
        let expected_delta = root.join("storage").join("Delta");
        for alias in [
            "/storage/emulated/0/Delta",
            "/storage/self/primary/Delta",
            "/mnt/sdcard/Delta",
            "/sdcard/Delta",
        ] {
            assert_eq!(map_android_path(root, alias).unwrap(), expected_delta);
        }
        assert_eq!(
            map_android_path(root, "/data/data/com.example/files").unwrap(),
            root.join("files")
        );
        assert_eq!(
            map_android_path(root, "/data/user/0/com.example/cache").unwrap(),
            root.join("cache")
        );
        assert_eq!(
            map_android_path(root, "/data/user/0/com.example/shared_prefs/settings.xml").unwrap(),
            root.join("data").join("shared_prefs").join("settings.xml")
        );
        assert_eq!(
            map_android_path(root, "/data/user_de/0/com.example/no_backup").unwrap(),
            root.join("data_de").join("no_backup")
        );
        assert_eq!(
            map_android_path(root, "/storage/emulated/0/Android/data/com.example/files").unwrap(),
            root.join("storage")
                .join("Android")
                .join("data")
                .join("com.example")
                .join("files")
        );
    }

    #[test]
    fn rejects_unmapped_and_traversal_paths() {
        let root = Path::new("/tmp/prbx");
        assert!(map_android_path(root, "/etc/passwd").is_err());
        assert!(map_android_path(root, "/storage/emulated/0/../secret").is_err());
        assert!(map_android_path(root, "/storage/emulated/0\\..\\secret").is_err());
        assert!(map_android_path(root, "/data/data/com.other/files").is_err());
        assert!(map_android_path(root, "/data/user/0/com.example.evil/files").is_err());
        assert!(map_android_path(root, "/data/user_de/0/com.other/files").is_err());
        assert!(
            map_android_path(root, "/storage/emulated/0/Android/data/com.other/files").is_err()
        );
        assert!(map_android_path(root, "storage/emulated/0/Delta").is_err());
        assert!(map_android_path(root, "/storage/emulated/0//Delta").is_err());
        assert!(map_android_path(root, "/storage/emulated/0/Delta/../secret").is_err());
        assert!(map_android_path(root, "/storage/emulated/0/C:/Windows").is_err());
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
    fn classifies_packaged_android_and_unknown_native_dependencies() {
        let roblox = native_library(
            "lib/arm64-v8a/libroblox.so",
            &[
                "libbacktrace-native.so",
                "libandroid.so",
                "libjnigraphics.so",
                "libGLESv3.so",
                "libmissing.so",
            ],
        );
        let backtrace = native_library("lib/arm64-v8a/libbacktrace-native.so", &["liblog.so"]);
        let libraries = [&roblox, &backtrace];

        let dependencies = native_dependencies(&libraries).unwrap();
        assert_eq!(
            dependencies
                .iter()
                .filter(|dependency| dependency.kind == DependencyKind::Packaged)
                .count(),
            1
        );
        assert_eq!(
            dependencies
                .iter()
                .filter(|dependency| dependency.kind == DependencyKind::AndroidPlatform)
                .count(),
            4
        );
        assert_eq!(
            dependencies
                .iter()
                .filter(|dependency| dependency.kind == DependencyKind::Unknown)
                .count(),
            1
        );
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
