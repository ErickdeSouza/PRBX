use std::{collections::BTreeMap, env, ffi::OsStr, path::Path, process::ExitCode};

use anyhow::{Result, bail};
use apk_inspector::{apk, jni};

const PRIORITIZED_FRAMEWORK_CALLS: usize = 20;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Erro: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let Some(apk_path) = args.next() else {
        bail!("uso: apk-inspector <arquivo.apk> [--symbols]");
    };
    if apk_path == OsStr::new("--help") || apk_path == OsStr::new("-h") {
        println!("Uso: apk-inspector <arquivo.apk> [--symbols]");
        println!("Inspeciona manifesto, DEX, bibliotecas ELF e indicadores JNI no APK.");
        return Ok(());
    }

    let show_symbols = match args.next() {
        Some(flag) if flag == OsStr::new("--symbols") => true,
        Some(_) => bail!("opção inválida; use --symbols ou --help"),
        None => false,
    };
    if args.next().is_some() {
        bail!("informe um caminho de APK e, opcionalmente, --symbols");
    }

    let report = apk::inspect(Path::new(&apk_path))?;
    println!("APK: {}", Path::new(&apk_path).display());
    match report.manifest_size {
        Some(size) => println!("AndroidManifest.xml: encontrado ({size} bytes, binário)"),
        None => println!("AndroidManifest.xml: ausente"),
    }
    if let Some(manifest) = &report.manifest {
        match manifest {
            Ok(manifest) => {
                println!(
                    "Pacote: {}",
                    manifest.package.as_deref().unwrap_or("(não identificado)")
                );
                if let Some(application) = &manifest.application_class {
                    println!("Classe Application: {application}");
                }
                if let Some(activity) = &manifest.launcher_activity {
                    println!("Activity launcher indicada: {activity}");
                }
                if let Some(min_sdk) = &manifest.min_sdk {
                    println!("SDK mínimo: {min_sdk}");
                }
                if let Some(target_sdk) = &manifest.target_sdk {
                    println!("SDK alvo: {target_sdk}");
                }
                println!("Componentes declarados: {}", manifest.components.len());
                println!("Permissões declaradas: {}", manifest.permissions.len());
                println!(
                    "Recursos de hardware declarados: {}",
                    manifest.features.len()
                );
                println!(
                    "Bibliotecas Android nativas declaradas: {}",
                    manifest.native_libraries.len()
                );
                if !manifest.metadata.is_empty() {
                    println!("Metadados Android declarados: {}", manifest.metadata.len());
                }
                if show_symbols {
                    for component in &manifest.components {
                        println!("  - {}: {}", component.kind, component.name);
                    }
                    for permission in &manifest.permissions {
                        println!("  - {permission}");
                    }
                    for feature in &manifest.features {
                        println!("  Recurso: {feature}");
                    }
                    for library in &manifest.native_libraries {
                        println!("  Biblioteca Android: {library}");
                    }
                    for (name, value) in &manifest.metadata {
                        println!("  Metadado: {name} = {value}");
                    }
                }
            }
            Err(error) => println!("Manifesto: não foi possível decodificar ({error})"),
        }
    }
    println!("Arquivos DEX: {}", report.dex_files.len());
    for dex_file in &report.dex_files {
        println!("  - {dex_file}");
    }
    for (dex_file, error) in &report.dex_errors {
        println!("  AVISO: não foi possível analisar {dex_file}: {error}");
    }
    println!(
        "Métodos nativos declarados nos DEX: {}",
        report.native_methods.len()
    );
    if show_symbols {
        for method in &report.native_methods {
            println!(
                "  - {}.{}{} [{}]",
                method.class_name, method.method_name, method.parameter_descriptor, method.dex_file
            );
        }
    }
    println!(
        "Chamadas a APIs Java/Android observadas no DEX: {} em {} referências de método distintas",
        report.framework_call_sites,
        report.framework_calls.len()
    );
    println!(
        "Classes de APIs Java/Android referenciadas: {}",
        report.framework_classes.len()
    );
    let mut api_namespaces = BTreeMap::new();
    for class in &report.framework_classes {
        let namespace = class
            .trim_start_matches('L')
            .trim_end_matches(';')
            .split('/')
            .take(2)
            .collect::<Vec<_>>()
            .join(".");
        *api_namespaces.entry(namespace).or_insert(0usize) += 1;
    }
    let mut api_namespaces = api_namespaces.into_iter().collect::<Vec<_>>();
    api_namespaces.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    println!("Namespaces de API mais referenciados:");
    for (namespace, count) in api_namespaces.iter().take(15) {
        println!("  - {namespace}: {count} classes");
    }
    let android_framework_call_sites = report
        .framework_calls
        .iter()
        .filter(|(method, _)| is_android_framework_call(method))
        .map(|(_, count)| count)
        .sum::<usize>();
    let android_framework_methods = report
        .framework_calls
        .keys()
        .filter(|method| is_android_framework_call(method))
        .count();
    println!(
        "Chamadas ao framework Android (android.*): {android_framework_call_sites} call sites em {android_framework_methods} referências de método distintas"
    );
    println!(
        "Chamadas ao framework Android mais frequentes (até {}):",
        PRIORITIZED_FRAMEWORK_CALLS
    );
    for (method, count) in prioritized_android_framework_calls(&report.framework_calls) {
        println!("  - {method} ({count} call sites)");
    }
    println!(
        "Chamadas Java/Android mais frequentes (até {}):",
        PRIORITIZED_FRAMEWORK_CALLS
    );
    for (method, count) in prioritized_framework_calls(&report.framework_calls) {
        println!("  - {method} ({count} call sites)");
    }
    println!(
        "Chamadas a carregadores de bibliotecas detectadas: {}",
        report.library_loads.len()
    );
    for load in &report.library_loads {
        println!(
            "  - {} chama {} [{}]",
            load.caller, load.target, load.dex_file
        );
        if let Some(argument) = &load.string_argument {
            println!("    Argumento resolvido por padrão const-string/invoke: {argument}");
            if load.target.ends_with("->loadLibrary") {
                let expected_file = format!("lib{argument}.so");
                let packaged = report.libraries.iter().find(|library| {
                    library.abi == "arm64-v8a"
                        && Path::new(&library.path)
                            .file_name()
                            .and_then(|name| name.to_str())
                            == Some(expected_file.as_str())
                });
                match packaged {
                    Some(library) => {
                        println!("    Biblioteca correspondente no APK: {}", library.path)
                    }
                    None => println!(
                        "    Nenhuma biblioteca correspondente encontrada no APK para {expected_file}"
                    ),
                }
            }
        } else if load.string_constants.is_empty() {
            println!("    (nenhuma string constante no método)");
        } else {
            println!("    Argumento não resolvido; strings no método são apenas candidatas:");
            for string in &load.string_constants {
                println!("      - {string}");
            }
        }
    }
    if show_symbols {
        println!("Métodos Android/Java chamados:");
        for (method, count) in &report.framework_calls {
            println!("  - {method} ({count})");
        }
    }

    let jni_links = jni::resolve_native_methods(&report.native_methods, &report.libraries);
    println!(
        "Associação JNI estática: {} correspondências convencionais ({} por descritor exato); {} ambiguidades de nome curto; {} sem correspondência",
        jni_links.conventional_matches,
        jni_links.exact_signature_matches,
        jni_links.ambiguous_short_names,
        jni_links.without_conventional_match
    );
    if !jni_links.on_load_libraries.is_empty() {
        println!(
            "Bibliotecas com JNI_OnLoad (podem registrar métodos dinamicamente; não é prova de registro): {}",
            jni_links.on_load_libraries.len()
        );
        if show_symbols {
            for library in &jni_links.on_load_libraries {
                println!("  - {library}");
            }
        }
    }
    if show_symbols {
        println!("Associações de métodos nativos DEX:");
        for method in &jni_links.methods {
            let resolution = match method.resolution {
                jni::NativeResolutionKind::ExactSignature => "descritor exato",
                jni::NativeResolutionKind::ShortName => "nome curto sem sobrecarga DEX",
                jni::NativeResolutionKind::AmbiguousShortName => "nome curto ambíguo",
                jni::NativeResolutionKind::Unmatched => "sem correspondência direta",
            };
            println!(
                "  - {}.{}{} [{}]: {}{}",
                method.class_name,
                method.method_name,
                method.parameter_descriptor,
                method.dex_file,
                resolution,
                if method.matching_exports.is_empty() {
                    String::new()
                } else {
                    format!(" -> {}", method.matching_exports.join(", "))
                }
            );
        }
        println!(
            "Nota: descritores exatos vêm do sufixo JNI de overload. Export sem sufixo só é associado automaticamente quando o DEX tem um único método nativo com esse nome. Métodos sem export Java_* podem depender de RegisterNatives, mas isso exige análise adicional."
        );
    }

    println!(
        "Bibliotecas nativas encontradas: {}",
        report.libraries.len()
    );
    for library in &report.libraries {
        println!("\n{} ({})", library.path, library.abi);
        println!(
            "  Tamanho: {} bytes ({} bytes comprimidos)",
            library.size, library.compressed_size
        );

        match &library.elf {
            Ok(elf_report) => {
                println!(
                    "  ELF: {} / {} / {} / {} endian",
                    elf_report.class,
                    elf_report.machine,
                    elf_report.object_type,
                    if elf_report.little_endian {
                        "little"
                    } else {
                        "big"
                    }
                );
                if !elf_report.abi_matches {
                    println!("  AVISO: arquitetura ELF não corresponde à pasta ABI");
                }
                println!(
                    "  Pré-validação para carregador ARM64: {}",
                    if elf_report.is_loadable_android_arm64_shared_object() {
                        "compatível (não executado)"
                    } else {
                        "incompatível"
                    }
                );
                let relocation_count = elf_report.relocation_types.values().sum::<usize>();
                println!(
                    "  Relocations dinâmicas ARM64: {relocation_count} em {} tipos",
                    elf_report.relocation_types.len()
                );
                if elf_report.needed.is_empty() {
                    println!("  NEEDED: nenhuma dependência declarada");
                } else {
                    println!("  NEEDED:");
                    for dependency in &elf_report.needed {
                        println!("    - {dependency}");
                    }
                }

                let jni_report = jni::analyze(&elf_report.exports);
                println!(
                    "  Símbolos dinâmicos: {} imports, {} exports",
                    elf_report.imports.len(),
                    elf_report.exports.len()
                );
                if !elf_report.android_api_imports.is_empty() {
                    println!("  Imports de APIs Android/NDK:");
                    for (group, count) in &elf_report.android_api_imports {
                        println!("    - {group}: {count}");
                    }
                }
                println!(
                    "  JNI: JNI_OnLoad {}; exports Java_* {}",
                    if jni_report.has_on_load {
                        "presente"
                    } else {
                        "ausente"
                    },
                    jni_report.java_exports.len()
                );

                if show_symbols {
                    println!("  Imports:");
                    for symbol in &elf_report.imports {
                        println!("    - {symbol}");
                    }
                    println!("  Exports:");
                    for symbol in &elf_report.exports {
                        println!("    - {symbol}");
                    }
                    println!("  Mapeamento JNI estimado:");
                    for export in &jni_report.java_exports {
                        match &export.method {
                            Some(method) => println!("    - {} -> {method}", export.symbol),
                            None => println!("    - {} -> nome não decodificado", export.symbol),
                        }
                    }
                }
            }
            Err(error) => println!("  ELF: não foi possível analisar ({error})"),
        }
    }

    Ok(())
}

fn prioritized_framework_calls(calls: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    let mut prioritized = calls
        .iter()
        .map(|(method, count)| (method.as_str(), *count))
        .collect::<Vec<_>>();
    prioritized.sort_by(|(left_method, left_count), (right_method, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_method.cmp(right_method))
    });
    prioritized.truncate(PRIORITIZED_FRAMEWORK_CALLS);
    prioritized
}

fn is_android_framework_call(method: &str) -> bool {
    method.starts_with("Landroid/")
}

fn prioritized_android_framework_calls(calls: &BTreeMap<String, usize>) -> Vec<(&str, usize)> {
    let mut prioritized = calls
        .iter()
        .filter(|(method, _)| is_android_framework_call(method))
        .map(|(method, count)| (method.as_str(), *count))
        .collect::<Vec<_>>();
    prioritized.sort_by(|(left_method, left_count), (right_method, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_method.cmp(right_method))
    });
    prioritized.truncate(PRIORITIZED_FRAMEWORK_CALLS);
    prioritized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prioritizes_framework_calls_by_frequency_with_stable_ties() {
        let calls = BTreeMap::from([
            ("Landroid/view/View;->draw".to_owned(), 8),
            ("Landroid/content/Context;->getSystemService".to_owned(), 12),
            ("Landroid/view/View;->invalidate".to_owned(), 8),
        ]);

        assert_eq!(
            prioritized_framework_calls(&calls),
            vec![
                ("Landroid/content/Context;->getSystemService", 12),
                ("Landroid/view/View;->draw", 8),
                ("Landroid/view/View;->invalidate", 8),
            ]
        );
    }

    #[test]
    fn limits_prioritized_framework_calls_to_twenty() {
        let calls = (0..25)
            .map(|index| (format!("Landroid/test/Api{index:02};->call"), index))
            .collect::<BTreeMap<_, _>>();

        let prioritized = prioritized_framework_calls(&calls);

        assert_eq!(prioritized.len(), PRIORITIZED_FRAMEWORK_CALLS);
        assert_eq!(prioritized[0].1, 24);
        assert_eq!(prioritized[19].1, 5);
    }

    #[test]
    fn prioritizes_android_calls_without_java_library_methods() {
        let calls = BTreeMap::from([
            ("Ljava/lang/StringBuilder;->append".to_owned(), 100),
            ("Landroid/view/View;->draw".to_owned(), 8),
            ("Landroid/content/Context;->getSystemService".to_owned(), 12),
            ("Landroidx/core/View;->draw".to_owned(), 50),
        ]);

        assert_eq!(
            prioritized_android_framework_calls(&calls),
            vec![
                ("Landroid/content/Context;->getSystemService", 12),
                ("Landroid/view/View;->draw", 8),
            ]
        );
    }
}
