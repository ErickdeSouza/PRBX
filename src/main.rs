use std::{collections::BTreeMap, env, ffi::OsStr, path::Path, process::ExitCode};

use anyhow::{Result, bail};
use apk_inspector::{apk, jni};

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
                "  - {}.{} [{}]",
                method.class_name, method.method_name, method.dex_file
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
    println!(
        "Chamadas a carregadores de bibliotecas detectadas: {}",
        report.library_loads.len()
    );
    for load in &report.library_loads {
        println!(
            "  - {} chama {} [{}]",
            load.caller, load.target, load.dex_file
        );
        if load.string_constants.is_empty() {
            println!("    (nenhuma string constante no método)");
        } else {
            println!("    Strings no método (candidatas; não prova valor passado):");
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
        "Associação JNI estática: {} métodos com export Java_* convencional; {} sem correspondência direta",
        jni_links.conventional_matches, jni_links.without_conventional_match
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
            if method.matching_exports.is_empty() {
                println!(
                    "  - {}.{} [{}]: sem export Java_* correspondente",
                    method.class_name, method.method_name, method.dex_file
                );
            } else {
                println!(
                    "  - {}.{} [{}]: {}",
                    method.class_name,
                    method.method_name,
                    method.dex_file,
                    method.matching_exports.join(", ")
                );
            }
        }
        println!(
            "Nota: a comparação usa classe e nome do método; não resolve sobrecargas por descritor JNI. Métodos sem export Java_* podem ser registrados via JNI_OnLoad, mas isso exige análise adicional."
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
                println!("  ELF: {} / {}", elf_report.class, elf_report.machine);
                if !elf_report.abi_matches {
                    println!("  AVISO: arquitetura ELF não corresponde à pasta ABI");
                }
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
