use std::{env, ffi::OsStr, path::PathBuf, process::ExitCode};

use anyhow::{Result, bail};
use apk_inspector::runtime;

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
    let Some(command) = args.next() else {
        print_usage();
        bail!("informe um comando");
    };
    if command == OsStr::new("--help") || command == OsStr::new("-h") {
        print_usage();
        return Ok(());
    }
    if command != OsStr::new("prepare") {
        print_usage();
        bail!("comando inválido");
    }

    let Some(apk_path) = args.next() else {
        print_usage();
        bail!("informe o caminho do APK");
    };
    let mut data_dir = runtime::default_data_dir()?;
    while let Some(option) = args.next() {
        if option != OsStr::new("--data-dir") {
            bail!("opção inválida; use --data-dir <diretório> ou --help");
        }
        let Some(path) = args.next() else {
            bail!("--data-dir exige um diretório");
        };
        data_dir = PathBuf::from(path);
    }

    let prepared = runtime::prepare(&PathBuf::from(apk_path), &data_dir)?;
    println!("APK preparado para: {}", prepared.package);
    println!("Diretório isolado: {}", prepared.app_root.display());
    println!("APK armazenado em: {}", prepared.apk_path.display());
    println!(
        "Configuração de inicialização: {}",
        prepared.launch_config.display()
    );
    if let Some(library) = &prepared.native_entry_library {
        println!("Biblioteca de entrada declarada: {library}");
    } else {
        println!("Biblioteca de entrada declarada: nenhuma");
    }
    println!("Bibliotecas ARM64 extraídas: {}", prepared.native_libraries);
    println!(
        "Assets extraídos: {} arquivos ({} bytes)",
        prepared.assets, prepared.asset_bytes
    );
    println!(
        "Mapa de dependências: {}",
        prepared.dependency_report.display()
    );
    println!(
        "Símbolos nativos importados: {} (inventário em {})",
        prepared.imported_symbols,
        prepared.symbol_report.display()
    );
    println!(
        "Plano de mapeamento ELF: {}",
        prepared.load_plan_report.display()
    );
    println!(
        "Teste de imagem ELF em buffer: {}",
        prepared.image_report.display()
    );
    println!(
        "Dependências ELF: {} no APK, {} de plataforma Android, {} não classificadas",
        prepared.packaged_dependencies,
        prepared.android_dependencies,
        prepared.unknown_dependencies
    );
    println!(
        "/storage/emulated/0/Delta -> {}",
        prepared.shared_storage.join("Delta").display()
    );
    println!("O carregamento Android/JNI e a execução do app ainda não estão implementados.");
    Ok(())
}

fn print_usage() {
    println!("Uso: prbx-runtime prepare <arquivo.apk> [--data-dir <diretório>]");
    println!("Prepara os arquivos do APK numa árvore isolada; não executa o app.");
}
