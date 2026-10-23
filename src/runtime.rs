use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
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
    pub symbol_report: PathBuf,
    pub load_plan_report: PathBuf,
    pub image_report: PathBuf,
    pub packaged_dependencies: usize,
    pub android_dependencies: usize,
    pub unknown_dependencies: usize,
    pub imported_symbols: usize,
    pub launch_config: PathBuf,
    pub native_entry_library: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AppLaunchConfig {
    pub schema_version: u32,
    pub package: String,
    pub abi: String,
    pub application_class: Option<String>,
    pub launcher_activity: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub native_library: Option<String>,
    pub apk_path: String,
    pub assets_path: String,
    pub private_data_path: String,
    pub cache_path: String,
    pub files_path: String,
    pub shared_storage_path: String,
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

struct NativeSymbol {
    library: String,
    group: &'static str,
    symbol: String,
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
        if !elf.is_loadable_android_arm64_shared_object() {
            bail!(
                "{} não é uma biblioteca ELF64 AArch64 little-endian ET_DYN com segmentos LOAD e DYNAMIC compatível com {TARGET_ABI}",
                library.path
            );
        }
    }
    let launch_config = build_launch_config(manifest, &target_libraries)?;
    let dependencies = native_dependencies(&target_libraries)?;
    let dependency_report = format!("native-dependencies-{TARGET_ABI}.txt");
    let symbols = native_symbols(&target_libraries)?;
    let symbol_report = format!("native-symbols-{TARGET_ABI}.txt");
    let load_plan_report = format!("native-load-plan-{TARGET_ABI}.txt");
    let image_report = format!("native-image-check-{TARGET_ABI}.txt");
    let launch_config_file = "launch-config.json";
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
    write_symbol_report(&staged_install.join(&symbol_report), &symbols)?;
    write_load_plan_report(&staged_install.join(&load_plan_report), &target_libraries)?;
    write_launch_config(&staged_install.join(launch_config_file), &launch_config)?;

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
            let archive_path = entry.name().to_owned();
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
            extract_entry(entry, &destination, &file_name)?;
            if !target_libraries
                .iter()
                .any(|library| library.path == archive_path)
            {
                bail!("não foi possível localizar a análise ELF de {archive_path}");
            }
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

    let mut mapped_images = Vec::with_capacity(target_libraries.len());
    let mut mapped_total_size = 0_u64;
    for library in &target_libraries {
        let file_name = Path::new(&library.path)
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("caminho de biblioteca inválido: {}", library.path))?;
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        let plan = elf
            .load_plan
            .as_ref()
            .with_context(|| format!("{} não tem plano de imagem ELF", library.path))?;
        mapped_total_size = mapped_total_size
            .checked_add(plan.image_size)
            .context("overflow no tamanho total das imagens ELF mapeadas")?;
        if mapped_total_size > MAX_TOTAL_LIBRARY_SIZE {
            bail!(
                "imagens ELF excedem o limite total de memória de {MAX_TOTAL_LIBRARY_SIZE} bytes"
            );
        }
        let native_bytes = fs::read(native_dir.join(file_name))
            .with_context(|| format!("não foi possível ler a biblioteca {file_name}"))?;
        let image = crate::elf::map_load_image(&native_bytes, plan, MAX_LIBRARY_SIZE)
            .with_context(|| format!("não foi possível mapear {}", library.path))?;
        mapped_images.push((file_name.to_owned(), image));
    }

    let load_order = native_load_order(&target_libraries, launch_config.native_library.as_deref())?;
    let mut image_checks = vec![format!(
        "Ordem de dependências empacotadas: {}",
        load_order.join(" -> ")
    )];
    for index in 0..mapped_images.len() {
        let file_name = mapped_images[index].0.clone();
        let library = target_libraries[index];
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        let plan = elf
            .load_plan
            .as_ref()
            .with_context(|| format!("{} não tem plano de imagem ELF", library.path))?;
        let scoped_symbols = packaged_symbol_scope(index, &target_libraries, &mapped_images)?;
        let image = &mut mapped_images[index].1;
        image
            .apply_relocations(plan, &elf.relocations, &scoped_symbols)
            .with_context(|| format!("falha ao aplicar relocations de {file_name}"))?;
        image_checks.push(format!(
            "{file_name}: {} bytes em mmap RW; {} RELATIVE e {} relocations com símbolos aplicadas; {} relocations pendentes; símbolos/tipos: {}{}",
            image.image_size(),
            image.relative_relocations_applied,
            image.symbol_relocations_applied,
            image.unresolved_relocation_count,
            image.unresolved_relocations.len(),
            if image.unresolved_relocations.is_empty() {
                String::new()
            } else {
                format!(" ({})", image.unresolved_relocations.join(", "))
            }
        ));
    }
    let library_indices = native_library_indices(&target_libraries)?;
    let mut init_sequences = Vec::new();
    let mut fini_sequences = Vec::new();
    for file_name in &load_order {
        let index = *library_indices
            .get(file_name)
            .with_context(|| format!("biblioteca {file_name} ausente no plano ELF"))?;
        let library = target_libraries[index];
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        let plan = elf
            .load_plan
            .as_ref()
            .with_context(|| format!("{} não tem plano de imagem ELF", library.path))?;
        let image = &mapped_images[index].1;
        let functions = image.resolve_init_functions(plan, &elf.init_plan)?;
        let init_offsets = functions
            .init_functions
            .iter()
            .map(|address| address - image.load_bias)
            .map(|address| format!("0x{address:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let fini_offsets = functions
            .fini_functions
            .iter()
            .map(|address| address - image.load_bias)
            .map(|address| format!("0x{address:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        init_sequences.push(format!("{file_name}: [{init_offsets}]"));
        fini_sequences.push(format!("{file_name}: [{fini_offsets}]"));
    }
    image_checks.push(format!(
        "Sequência DT_INIT/DT_INIT_ARRAY em ordem de dependências (planejada, não executada): {}",
        init_sequences.join(" -> ")
    ));
    fini_sequences.reverse();
    image_checks.push(format!(
        "Sequência DT_FINI_ARRAY/DT_FINI em ordem de descarregamento (planejada, não executada): {}",
        fini_sequences.join(" -> ")
    ));

    write_image_check_report(&staged_install.join(&image_report), &image_checks)?;
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
        symbol_report: install_dir.join(&symbol_report),
        load_plan_report: install_dir.join(&load_plan_report),
        image_report: install_dir.join(&image_report),
        packaged_dependencies,
        android_dependencies,
        unknown_dependencies,
        imported_symbols: symbols.len(),
        launch_config: install_dir.join(launch_config_file),
        native_entry_library: launch_config.native_library.clone(),
    })
}

fn build_launch_config(
    manifest: &crate::analysis::manifest::ManifestReport,
    libraries: &[&crate::apk::NativeLibrary],
) -> Result<AppLaunchConfig> {
    let package = manifest
        .package
        .as_deref()
        .context("o manifesto não informa o nome do pacote")?;
    validate_package_name(package)?;
    let native_library = manifest
        .metadata
        .iter()
        .find(|(name, _)| name == "android.app.lib_name")
        .map(|(_, value)| native_library_path(value))
        .transpose()?;
    if let Some(expected_path) = &native_library
        && !libraries.iter().any(|library| {
            Path::new(&library.path)
                .file_name()
                .and_then(|name| name.to_str())
                == Path::new(expected_path)
                    .file_name()
                    .and_then(|name| name.to_str())
        })
    {
        bail!(
            "a biblioteca de entrada declarada no manifesto ({expected_path}) não foi encontrada para a ABI {TARGET_ABI}"
        );
    }

    Ok(AppLaunchConfig {
        schema_version: 1,
        package: package.to_owned(),
        abi: TARGET_ABI.to_owned(),
        application_class: manifest.application_class.clone(),
        launcher_activity: manifest.launcher_activity.clone(),
        min_sdk: manifest.min_sdk.clone(),
        target_sdk: manifest.target_sdk.clone(),
        native_library,
        apk_path: "apk/base.apk".to_owned(),
        assets_path: "assets".to_owned(),
        private_data_path: "../data".to_owned(),
        cache_path: "../cache".to_owned(),
        files_path: "../files".to_owned(),
        shared_storage_path: "../storage".to_owned(),
    })
}

fn native_library_path(value: &str) -> Result<String> {
    let name = value
        .strip_prefix("lib")
        .and_then(|name| name.strip_suffix(".so"))
        .unwrap_or(value);
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("android.app.lib_name contém nome de biblioteca inválido: {value}");
    }
    Ok(format!("native/{TARGET_ABI}/lib{name}.so"))
}

fn write_launch_config(path: &Path, config: &AppLaunchConfig) -> Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(config).context("falha ao serializar configuração")?;
    bytes.push(b'\n');
    fs::write(path, bytes)
        .with_context(|| format!("não foi possível gravar configuração {}", path.display()))
}

fn native_symbols(libraries: &[&crate::apk::NativeLibrary]) -> Result<Vec<NativeSymbol>> {
    let mut symbols = BTreeSet::new();
    for library in libraries {
        let file_name = Path::new(&library.path)
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("caminho de biblioteca inválido: {}", library.path))?;
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        for symbol in &elf.imports {
            symbols.insert((
                file_name.to_owned(),
                crate::elf::import_group(symbol),
                symbol.clone(),
            ));
        }
    }
    Ok(symbols
        .into_iter()
        .map(|(library, group, symbol)| NativeSymbol {
            library,
            group,
            symbol,
        })
        .collect())
}

fn write_symbol_report(path: &Path, symbols: &[NativeSymbol]) -> Result<()> {
    use std::fmt::Write as _;

    let mut report = String::from(
        "Símbolos dinâmicos indefinidos observados estaticamente nas bibliotecas do APK.\n\
Eles são requisitos de resolução ELF; não indicam por si só chamadas executadas nem APIs ausentes no host.\n",
    );
    let mut current_library = "";
    for symbol in symbols {
        if symbol.library != current_library {
            current_library = &symbol.library;
            writeln!(report, "\n[{}]", symbol.library).expect("escrever em String não falha");
        }
        writeln!(report, "{} | {}", symbol.group, symbol.symbol)
            .expect("escrever em String não falha");
    }
    fs::write(path, report)
        .with_context(|| format!("não foi possível gravar o relatório {}", path.display()))
}

fn write_load_plan_report(path: &Path, libraries: &[&crate::apk::NativeLibrary]) -> Result<()> {
    use std::fmt::Write as _;

    let mut report = String::from(
        "Plano estrutural de mapeamento ELF por páginas e inventário de relocations; não reserva memória, aplica relocations nem executa código.\n",
    );
    for library in libraries {
        let name = Path::new(&library.path)
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("caminho de biblioteca inválido: {}", library.path))?;
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        let plan = elf
            .load_plan
            .as_ref()
            .with_context(|| format!("{} não contém segmentos PT_LOAD", library.path))?;
        writeln!(
            report,
            "\n[{name}] imagem 0x{:x}..0x{:x} ({} bytes; página {})",
            plan.image_start, plan.image_end, plan.image_size, plan.page_size
        )
        .expect("escrever em String não falha");
        if let Some(soname) = &elf.soname {
            writeln!(report, "SONAME: {soname}").expect("escrever em String não falha");
        }
        if let Some(init) = elf.init_plan.init {
            writeln!(report, "DT_INIT: 0x{init:x}").expect("escrever em String não falha");
        }
        if let Some((address, size)) = elf.init_plan.init_array {
            writeln!(report, "DT_INIT_ARRAY: 0x{address:x} ({size} bytes)")
                .expect("escrever em String não falha");
        }
        if let Some(fini) = elf.init_plan.fini {
            writeln!(report, "DT_FINI: 0x{fini:x}").expect("escrever em String não falha");
        }
        if let Some((address, size)) = elf.init_plan.fini_array {
            writeln!(report, "DT_FINI_ARRAY: 0x{address:x} ({size} bytes)")
                .expect("escrever em String não falha");
        }
        if let Some(tls) = &elf.tls_plan {
            writeln!(
                report,
                "PT_TLS: vaddr=0x{:x} file=0x{:x}+0x{:x} mem=0x{:x} align=0x{:x}",
                tls.virtual_address, tls.file_offset, tls.file_size, tls.memory_size, tls.alignment
            )
            .expect("escrever em String não falha");
        }
        if elf.relocation_types.is_empty() {
            writeln!(report, "Relocations dinâmicas: nenhuma")
                .expect("escrever em String não falha");
        } else {
            writeln!(report, "Relocations dinâmicas:").expect("escrever em String não falha");
            for (relocation, count) in &elf.relocation_types {
                writeln!(report, "  {relocation}: {count}").expect("escrever em String não falha");
            }
        }
        writeln!(
            report,
            "Suporte dinâmico: RELATIVE (RELA e DT_RELR), ABS64/32/16, PREL64/32/16, GLOB_DAT e JUMP_SLOT; veja native-image-check"
        )
        .expect("escrever em String não falha");
        let versioned_imports = elf
            .relocations
            .iter()
            .filter_map(|relocation| {
                let symbol = relocation.symbol_name.as_deref()?;
                let version = relocation.symbol_version.as_ref()?;
                Some((
                    symbol.to_owned(),
                    version.name.clone(),
                    version.hash,
                    version.hidden,
                ))
            })
            .collect::<BTreeSet<_>>();
        for (symbol, version, hash, hidden) in versioned_imports {
            writeln!(
                report,
                "Import versionado: {symbol}@{version} hash=0x{hash:08x} hidden={hidden}"
            )
            .expect("escrever em String não falha");
        }
        let unknown_versions = elf
            .relocations
            .iter()
            .filter(|relocation| relocation.symbol_version_unknown)
            .count();
        if unknown_versions > 0 {
            writeln!(
                report,
                "Relocations com versão ELF não decodificada: {unknown_versions} (mantidas pendentes)"
            )
            .expect("escrever em String não falha");
        }
        for (index, segment) in plan.segments.iter().enumerate() {
            let permissions = format!(
                "{}{}{}",
                if segment.readable { 'r' } else { '-' },
                if segment.writable { 'w' } else { '-' },
                if segment.executable { 'x' } else { '-' }
            );
            writeln!(
                report,
                "PT_LOAD {index}: vaddr=0x{:x} map=0x{:x}..0x{:x} file=0x{:x}+0x{:x} mem=0x{:x} bss=0x{:x} align=0x{:x} flags={permissions}",
                segment.virtual_address,
                segment.mapped_start,
                segment.mapped_end,
                segment.file_offset,
                segment.file_size,
                segment.memory_size,
                segment.memory_size - segment.file_size,
                segment.alignment
            )
            .expect("escrever em String não falha");
        }
    }
    fs::write(path, report)
        .with_context(|| format!("não foi possível gravar o relatório {}", path.display()))
}

fn write_image_check_report(path: &Path, checks: &[String]) -> Result<()> {
    let mut report = String::from(
        "Imagens mapeadas em memória virtual RW durante prepare; relocations relativas e símbolos entre bibliotecas do APK tentados.\n\
Mapeamentos são descartados ao terminar prepare, páginas não executáveis, símbolos Android não fornecidos continuam pendentes.\n",
    );
    for check in checks {
        report.push_str(check);
        report.push('\n');
    }
    fs::write(path, report)
        .with_context(|| format!("não foi possível gravar o relatório {}", path.display()))
}

fn native_load_order(
    libraries: &[&crate::apk::NativeLibrary],
    entry_library: Option<&str>,
) -> Result<Vec<String>> {
    fn visit(
        index: usize,
        libraries: &[&crate::apk::NativeLibrary],
        indices: &BTreeMap<String, usize>,
        visiting: &mut BTreeSet<usize>,
        loaded: &mut BTreeSet<usize>,
        order: &mut Vec<String>,
    ) -> Result<()> {
        if loaded.contains(&index) || !visiting.insert(index) {
            return Ok(());
        }
        let library = libraries[index];
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        for dependency in &elf.needed {
            if let Some(dependency_index) = indices.get(dependency) {
                visit(
                    *dependency_index,
                    libraries,
                    indices,
                    visiting,
                    loaded,
                    order,
                )?;
            }
        }
        visiting.remove(&index);
        if loaded.insert(index) {
            order.push(
                Path::new(&library.path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .with_context(|| format!("caminho ELF inválido: {}", library.path))?
                    .to_owned(),
            );
        }
        Ok(())
    }

    let indices = native_library_indices(libraries)?;
    let mut roots = Vec::new();
    if let Some(entry_library) = entry_library {
        let name = Path::new(entry_library)
            .file_name()
            .and_then(|name| name.to_str())
            .context("caminho da biblioteca de entrada inválido")?;
        let index = indices
            .get(name)
            .with_context(|| format!("biblioteca de entrada {name} não está empacotada"))?;
        roots.push(*index);
    }
    roots.extend(0..libraries.len());

    let mut order = Vec::new();
    let mut visiting = BTreeSet::new();
    let mut loaded = BTreeSet::new();
    for root in roots {
        visit(
            root,
            libraries,
            &indices,
            &mut visiting,
            &mut loaded,
            &mut order,
        )?;
    }
    Ok(order)
}

fn packaged_symbol_scope(
    importer_index: usize,
    libraries: &[&crate::apk::NativeLibrary],
    images: &[(String, crate::elf::MappedElfImage)],
) -> Result<BTreeMap<String, u64>> {
    let indices = native_library_indices(libraries)?;
    let importer = libraries
        .get(importer_index)
        .context("índice da biblioteca importadora inválido")?;
    let importer_elf = importer
        .elf
        .as_ref()
        .map_err(|error| anyhow::anyhow!("{}: {error}", importer.path))?;
    let mut queue = VecDeque::from(importer_elf.needed.clone());
    let mut visited = BTreeSet::new();
    let mut symbols = BTreeMap::<String, (u64, bool)>::new();

    while let Some(dependency) = queue.pop_front() {
        let Some(index) = indices.get(&dependency).copied() else {
            continue;
        };
        if !visited.insert(index) {
            continue;
        }
        let library = libraries[index];
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        let load_bias = images
            .get(index)
            .context("imagem mapeada ausente para dependência empacotada")?
            .1
            .load_bias;
        for symbol in &elf.dynamic_symbols {
            if !symbol.defined
                || !symbol.visible
                || symbol.version_unknown
                || !(symbol.global || symbol.weak)
            {
                continue;
            }
            let address = if symbol.absolute {
                symbol.value
            } else {
                load_bias
                    .checked_add(symbol.value)
                    .with_context(|| format!("endereço ELF excedido para {}", symbol.name))?
            };
            let versioned_key =
                crate::elf::symbol_lookup_key(&symbol.name, symbol.version.as_ref());
            insert_scoped_symbol(&mut symbols, versioned_key, address, symbol.weak);
            if symbol
                .version
                .as_ref()
                .is_none_or(|version| !version.hidden)
            {
                insert_scoped_symbol(&mut symbols, symbol.name.clone(), address, symbol.weak);
            }
        }
        queue.extend(elf.needed.iter().cloned());
    }

    let mut scope = BTreeMap::new();
    for (name, (address, _)) in symbols {
        scope.insert(name, address);
    }
    Ok(scope)
}

fn insert_scoped_symbol(
    symbols: &mut BTreeMap<String, (u64, bool)>,
    key: String,
    address: u64,
    weak: bool,
) {
    match symbols.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert((address, weak));
        }
        std::collections::btree_map::Entry::Occupied(mut entry) if entry.get().1 && !weak => {
            entry.insert((address, false));
        }
        std::collections::btree_map::Entry::Occupied(_) => {}
    }
}

fn native_library_indices(
    libraries: &[&crate::apk::NativeLibrary],
) -> Result<BTreeMap<String, usize>> {
    let mut indices = BTreeMap::new();
    for (index, library) in libraries.iter().enumerate() {
        let elf = library
            .elf
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{}: {error}", library.path))?;
        let file_name = Path::new(&library.path)
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("caminho ELF inválido: {}", library.path))?;
        for name in std::iter::once(file_name).chain(elf.soname.as_deref()) {
            if let Some(previous) = indices.insert(name.to_owned(), index)
                && previous != index
            {
                bail!("identidade de biblioteca nativa ambígua: {name}");
            }
        }
    }
    Ok(indices)
}

fn native_dependencies(libraries: &[&crate::apk::NativeLibrary]) -> Result<Vec<NativeDependency>> {
    let packaged = native_library_indices(libraries)?
        .into_keys()
        .collect::<BTreeSet<_>>();

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
    use crate::analysis::manifest::ManifestReport;
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
                object_type: "ET_DYN",
                little_endian: true,
                abi_matches: true,
                has_load_segment: true,
                has_dynamic_segment: true,
                load_plan: Some(crate::elf::ElfLoadPlan {
                    page_size: 4096,
                    image_start: 0,
                    image_end: 4096,
                    image_size: 4096,
                    segments: Vec::new(),
                }),
                init_plan: crate::elf::ElfInitPlan::default(),
                tls_plan: None,
                relocation_types: BTreeMap::new(),
                relocations: Vec::new(),
                dynamic_symbols: Vec::new(),
                soname: None,
                needed: needed.iter().map(|name| (*name).to_owned()).collect(),
                imports: Vec::new(),
                exports: Vec::new(),
                android_api_imports: BTreeMap::new(),
            }),
        }
    }

    fn manifest_with_library(name: &str, value: &str) -> ManifestReport {
        ManifestReport {
            package: Some("com.example".to_owned()),
            application_class: Some("com.example.App".to_owned()),
            launcher_activity: Some("com.example.MainActivity".to_owned()),
            min_sdk: Some("26".to_owned()),
            target_sdk: Some("35".to_owned()),
            metadata: vec![(name.to_owned(), value.to_owned())],
            ..ManifestReport::default()
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
    fn matches_packaged_libraries_by_soname_and_rejects_ambiguous_identities() {
        let app = native_library("lib/arm64-v8a/libapp.so", &["libcomponent.so"]);
        let mut component = native_library("lib/arm64-v8a/libcomponent-v2.so", &[]);
        component.elf.as_mut().unwrap().soname = Some("libcomponent.so".to_owned());
        let libraries = [&app, &component];

        assert_eq!(
            native_load_order(&libraries, Some("libapp.so")).unwrap(),
            vec!["libcomponent-v2.so", "libapp.so"]
        );
        assert!(native_dependencies(&libraries).unwrap()[0].kind == DependencyKind::Packaged);

        let mut duplicate = native_library("lib/arm64-v8a/libduplicate.so", &[]);
        duplicate.elf.as_mut().unwrap().soname = Some("libcomponent.so".to_owned());
        let ambiguous = [&app, &component, &duplicate];
        assert!(native_library_indices(&ambiguous).is_err());
    }

    #[test]
    fn orders_packaged_libraries_dependencies_first_and_breaks_cycles() {
        let app = native_library("lib/arm64-v8a/libapp.so", &["libfirst.so", "libsecond.so"]);
        let first = native_library("lib/arm64-v8a/libfirst.so", &["libtransitive.so"]);
        let second = native_library("lib/arm64-v8a/libsecond.so", &[]);
        let transitive = native_library("lib/arm64-v8a/libtransitive.so", &[]);
        let libraries = [&app, &first, &second, &transitive];

        assert_eq!(
            native_load_order(&libraries, Some("native/arm64-v8a/libapp.so")).unwrap(),
            vec![
                "libtransitive.so",
                "libfirst.so",
                "libsecond.so",
                "libapp.so"
            ]
        );

        let cycle_a = native_library("lib/arm64-v8a/libcycle-a.so", &["libcycle-b.so"]);
        let cycle_b = native_library("lib/arm64-v8a/libcycle-b.so", &["libcycle-a.so"]);
        assert_eq!(
            native_load_order(&[&cycle_a, &cycle_b], Some("libcycle-a.so")).unwrap(),
            vec!["libcycle-b.so", "libcycle-a.so"]
        );
    }

    #[test]
    fn resolves_symbols_only_from_needed_dependency_scope_with_strong_precedence() {
        let mut libraries = vec![
            native_library("lib/arm64-v8a/libapp.so", &["libfirst.so", "libsecond.so"]),
            native_library("lib/arm64-v8a/libfirst.so", &["libtransitive.so"]),
            native_library("lib/arm64-v8a/libsecond.so", &[]),
            native_library("lib/arm64-v8a/libtransitive.so", &[]),
            native_library("lib/arm64-v8a/libunrelated.so", &[]),
        ];

        libraries[1]
            .elf
            .as_mut()
            .unwrap()
            .dynamic_symbols
            .push(crate::elf::ElfDynamicSymbol {
                name: "shared_symbol".to_owned(),
                value: 0x20,
                defined: true,
                absolute: false,
                global: false,
                weak: true,
                visible: true,
                version: None,
                version_unknown: false,
            });
        libraries[2]
            .elf
            .as_mut()
            .unwrap()
            .dynamic_symbols
            .push(crate::elf::ElfDynamicSymbol {
                name: "shared_symbol".to_owned(),
                value: 0x30,
                defined: true,
                absolute: false,
                global: true,
                weak: false,
                visible: true,
                version: None,
                version_unknown: false,
            });
        libraries[3]
            .elf
            .as_mut()
            .unwrap()
            .dynamic_symbols
            .push(crate::elf::ElfDynamicSymbol {
                name: "transitive_symbol".to_owned(),
                value: 0x40,
                defined: true,
                absolute: false,
                global: true,
                weak: false,
                visible: true,
                version: None,
                version_unknown: false,
            });
        libraries[4]
            .elf
            .as_mut()
            .unwrap()
            .dynamic_symbols
            .push(crate::elf::ElfDynamicSymbol {
                name: "unrelated_symbol".to_owned(),
                value: 0x50,
                defined: true,
                absolute: false,
                global: true,
                weak: false,
                visible: true,
                version: None,
                version_unknown: false,
            });
        libraries[1].elf.as_mut().unwrap().dynamic_symbols.extend([
            crate::elf::ElfDynamicSymbol {
                name: "compat_api".to_owned(),
                value: 0x60,
                defined: true,
                absolute: false,
                global: true,
                weak: false,
                visible: true,
                version: Some(crate::elf::ElfSymbolVersion {
                    name: "LIB_1".to_owned(),
                    hash: 0x1111,
                    hidden: true,
                }),
                version_unknown: false,
            },
            crate::elf::ElfDynamicSymbol {
                name: "compat_api".to_owned(),
                value: 0x70,
                defined: true,
                absolute: false,
                global: true,
                weak: false,
                visible: true,
                version: Some(crate::elf::ElfSymbolVersion {
                    name: "LIB_2".to_owned(),
                    hash: 0x2222,
                    hidden: false,
                }),
                version_unknown: false,
            },
        ]);

        let library_refs = libraries.iter().collect::<Vec<_>>();
        let images = library_refs
            .iter()
            .map(|library| {
                let name = Path::new(&library.path)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
                let plan = library.elf.as_ref().unwrap().load_plan.as_ref().unwrap();
                let image = crate::elf::map_load_image(&[], plan, 4096).unwrap();
                (name, image)
            })
            .collect::<Vec<_>>();
        let scope = packaged_symbol_scope(0, &library_refs, &images).unwrap();

        assert_eq!(scope["shared_symbol"], images[2].1.load_bias + 0x30);
        assert_eq!(scope["transitive_symbol"], images[3].1.load_bias + 0x40);
        assert!(!scope.contains_key("unrelated_symbol"));
        assert_eq!(scope["compat_api"], images[1].1.load_bias + 0x70);
        assert_eq!(
            scope[&crate::elf::symbol_lookup_key(
                "compat_api",
                Some(&crate::elf::ElfSymbolVersion {
                    name: "LIB_1".to_owned(),
                    hash: 0x1111,
                    hidden: true,
                })
            )],
            images[1].1.load_bias + 0x60
        );
        assert_eq!(
            scope[&crate::elf::symbol_lookup_key(
                "compat_api",
                Some(&crate::elf::ElfSymbolVersion {
                    name: "LIB_2".to_owned(),
                    hash: 0x2222,
                    hidden: false,
                })
            )],
            images[1].1.load_bias + 0x70
        );
    }

    #[test]
    fn inventories_unique_undefined_symbols_by_native_library() {
        let mut library = native_library("lib/arm64-v8a/libroblox.so", &[]);
        library.elf.as_mut().unwrap().imports = vec![
            "eglInitialize".to_owned(),
            "JNI_OnLoad".to_owned(),
            "eglInitialize".to_owned(),
            "__cxa_throw".to_owned(),
        ];

        let symbols = native_symbols(&[&library]).unwrap();
        assert_eq!(symbols.len(), 3);
        assert!(
            symbols
                .iter()
                .any(|symbol| symbol.group == "EGL" && symbol.symbol == "eglInitialize")
        );
        assert!(
            symbols
                .iter()
                .any(|symbol| symbol.group == "JNI" && symbol.symbol == "JNI_OnLoad")
        );
        assert!(
            symbols
                .iter()
                .all(|symbol| symbol.library == "libroblox.so")
        );
    }

    #[test]
    fn rejects_invalid_package_names() {
        assert!(validate_package_name("com.roblox.client").is_ok());
        assert!(validate_package_name("../outside").is_err());
        assert!(validate_package_name("com..client").is_err());
    }

    #[test]
    fn builds_bootstrap_config_from_manifest_and_validates_entry_library() {
        let manifest = manifest_with_library("android.app.lib_name", "roblox");
        let library = native_library("lib/arm64-v8a/libroblox.so", &[]);
        let config = build_launch_config(&manifest, &[&library]).unwrap();

        assert_eq!(config.schema_version, 1);
        assert_eq!(config.package, "com.example");
        assert_eq!(config.abi, "arm64-v8a");
        assert_eq!(
            config.launcher_activity.as_deref(),
            Some("com.example.MainActivity")
        );
        assert_eq!(
            config.native_library.as_deref(),
            Some("native/arm64-v8a/libroblox.so")
        );
        assert_eq!(config.apk_path, "apk/base.apk");
    }

    #[test]
    fn rejects_missing_or_unsafe_manifest_entry_library() {
        let manifest = manifest_with_library("android.app.lib_name", "roblox");
        assert!(
            build_launch_config(&manifest, &[])
                .unwrap_err()
                .to_string()
                .contains("não foi encontrada")
        );

        for invalid in ["../outside", "roblox/path", ""] {
            assert!(native_library_path(invalid).is_err());
        }
    }

    #[test]
    fn serializes_launch_config_as_parseable_json() {
        let manifest = manifest_with_library("android.app.lib_name", "libroblox.so");
        let library = native_library("lib/arm64-v8a/libroblox.so", &[]);
        let config = build_launch_config(&manifest, &[&library]).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: AppLaunchConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.package, "com.example");
        assert_eq!(
            decoded.native_library.as_deref(),
            Some("native/arm64-v8a/libroblox.so")
        );
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
