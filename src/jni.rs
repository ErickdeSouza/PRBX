use crate::{analysis::dex::NativeMethod, apk::NativeLibrary};

pub struct JniReport<'a> {
    pub has_on_load: bool,
    pub java_exports: Vec<JavaExport<'a>>,
}

pub struct NativeMethodResolution {
    pub class_name: String,
    pub method_name: String,
    pub dex_file: String,
    pub matching_exports: Vec<String>,
}

pub struct NativeLinkReport {
    pub methods: Vec<NativeMethodResolution>,
    pub conventional_matches: usize,
    pub without_conventional_match: usize,
    pub on_load_libraries: Vec<String>,
}

pub struct JavaExport<'a> {
    pub symbol: &'a str,
    pub method: Option<String>,
}

pub fn analyze(exports: &[String]) -> JniReport<'_> {
    let has_on_load = exports.iter().any(|name| {
        name == "JNI_OnLoad" || name.starts_with("JNI_OnLoad@") || name.starts_with("JNI_OnLoad@@")
    });
    let java_exports = exports
        .iter()
        .filter(|name| name.starts_with("Java_"))
        .map(|symbol| JavaExport {
            symbol,
            method: decode_native_method(symbol),
        })
        .collect();

    JniReport {
        has_on_load,
        java_exports,
    }
}

pub fn resolve_native_methods(
    methods: &[NativeMethod],
    libraries: &[NativeLibrary],
) -> NativeLinkReport {
    let mut exports_by_method = Vec::new();
    let mut on_load_libraries = Vec::new();

    for library in libraries {
        let Ok(elf) = &library.elf else {
            continue;
        };
        let jni_report = analyze(&elf.exports);
        if jni_report.has_on_load {
            on_load_libraries.push(format!("{} ({})", library.path, library.abi));
        }
        for export in jni_report.java_exports {
            let Some(method) = export.method else {
                continue;
            };
            let Some((class_name, method_name)) = method.rsplit_once('.') else {
                continue;
            };
            exports_by_method.push((
                class_name.replace('/', "."),
                method_name.to_owned(),
                format!("{}:{} ({})", library.path, export.symbol, library.abi),
            ));
        }
    }

    let mut conventional_matches = 0;
    let mut resolutions = Vec::with_capacity(methods.len());
    for method in methods {
        let matching_exports = exports_by_method
            .iter()
            .filter(|(class, name, _)| class == &method.class_name && name == &method.method_name)
            .map(|(_, _, export)| export.clone())
            .collect::<Vec<_>>();
        if matching_exports.is_empty() {
            resolutions.push(NativeMethodResolution {
                class_name: method.class_name.clone(),
                method_name: method.method_name.clone(),
                dex_file: method.dex_file.clone(),
                matching_exports,
            });
        } else {
            conventional_matches += 1;
            resolutions.push(NativeMethodResolution {
                class_name: method.class_name.clone(),
                method_name: method.method_name.clone(),
                dex_file: method.dex_file.clone(),
                matching_exports,
            });
        }
    }
    on_load_libraries.sort();
    NativeLinkReport {
        without_conventional_match: resolutions.len() - conventional_matches,
        methods: resolutions,
        conventional_matches,
        on_load_libraries,
    }
}

fn decode_native_method(symbol: &str) -> Option<String> {
    let encoded = symbol.strip_prefix("Java_")?;
    let encoded = encoded.split_once("__").map_or(encoded, |(name, _)| name);
    let separator = encoded
        .char_indices()
        .rev()
        .find_map(|(index, character)| {
            if character != '_' {
                return None;
            }
            let next = encoded[index + 1..].chars().next()?;
            (!matches!(next, '0' | '1' | '2' | '3')).then_some(index)
        })?;
    let (class, method) = encoded.split_at(separator);
    let method = method.strip_prefix('_')?;
    Some(format!(
        "{}.{}",
        decode_jni_name(class, true)?,
        decode_jni_name(method, false)?
    ))
}

fn decode_jni_name(encoded: &str, class_name: bool) -> Option<String> {
    let mut decoded = String::new();
    let mut chars = encoded.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '_' {
            decoded.push(character);
            continue;
        }

        match chars.peek().copied()? {
            '1' => {
                chars.next();
                decoded.push('_');
            }
            '2' => {
                chars.next();
                decoded.push(';');
            }
            '3' => {
                chars.next();
                decoded.push('[');
            }
            '0' => {
                chars.next();
                let hex = chars.by_ref().take(4).collect::<String>();
                if hex.len() != 4 {
                    return None;
                }
                let code_point = u32::from_str_radix(&hex, 16).ok()?;
                decoded.push(char::from_u32(code_point)?);
            }
            _ if class_name => decoded.push('/'),
            _ => return None,
        }
    }

    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfReport;
    use std::collections::BTreeMap;

    fn library(path: &str, exports: &[&str]) -> NativeLibrary {
        NativeLibrary {
            path: path.to_owned(),
            abi: "arm64-v8a".to_owned(),
            size: 0,
            compressed_size: 0,
            elf: Ok(ElfReport {
                class: "ELF64",
                machine: "AArch64",
                abi_matches: true,
                needed: Vec::new(),
                imports: Vec::new(),
                exports: exports.iter().map(|name| (*name).to_owned()).collect(),
                android_api_imports: BTreeMap::new(),
            }),
        }
    }

    fn native_method(class_name: &str, method_name: &str) -> NativeMethod {
        NativeMethod {
            class_name: class_name.to_owned(),
            method_name: method_name.to_owned(),
            dex_file: "classes.dex".to_owned(),
        }
    }

    #[test]
    fn reports_jni_entry_point_and_native_method_exports() {
        let exports = vec![
            "JNI_OnLoad".to_owned(),
            "Java_com_example_Native_init".to_owned(),
            "some_other_export".to_owned(),
        ];
        let report = analyze(&exports);
        assert!(report.has_on_load);
        assert_eq!(
            report.java_exports[0].method.as_deref(),
            Some("com/example/Native.init")
        );
    }

    #[test]
    fn supports_dynamic_registration_without_java_named_exports() {
        let exports = ["JNI_OnLoad@@LIBRARY".to_owned()];
        let report = analyze(&exports);
        assert!(report.has_on_load);
        assert!(report.java_exports.is_empty());
    }

    #[test]
    fn decodes_jni_escapes_and_overload_suffix() {
        assert_eq!(
            decode_native_method("Java_com_example_Native_native_1init__I"),
            Some("com/example/Native.native_init".to_owned())
        );
        assert_eq!(decode_native_method("Java_invalid"), None);
    }

    #[test]
    fn correlates_dex_native_methods_with_conventional_exports() {
        let methods = vec![
            native_method("com.example.Native", "start"),
            native_method("com.example.Native", "missing"),
        ];
        let libraries = vec![library(
            "lib/arm64-v8a/libnative.so",
            &["JNI_OnLoad", "Java_com_example_Native_start"],
        )];

        let report = resolve_native_methods(&methods, &libraries);
        assert_eq!(report.conventional_matches, 1);
        assert_eq!(report.without_conventional_match, 1);
        assert_eq!(report.methods[0].matching_exports.len(), 1);
        assert!(
            report.methods[0].matching_exports[0]
                .contains("libnative.so:Java_com_example_Native_start")
        );
        assert_eq!(
            report.on_load_libraries,
            ["lib/arm64-v8a/libnative.so (arm64-v8a)"]
        );
    }

    #[test]
    fn matches_encoded_jni_names_but_does_not_claim_unmatched_registration() {
        let methods = vec![
            native_method("com.example.Native", "native_init"),
            native_method("com.example.Other", "init"),
        ];
        let libraries = vec![library(
            "lib/arm64-v8a/libnative.so",
            &["JNI_OnLoad", "Java_com_example_Native_native_1init__I"],
        )];

        let report = resolve_native_methods(&methods, &libraries);
        assert_eq!(report.conventional_matches, 1);
        assert_eq!(report.without_conventional_match, 1);
        assert!(report.methods[0].matching_exports[0].contains("native_1init__I"));
        assert!(report.methods[1].matching_exports.is_empty());
        assert_eq!(report.on_load_libraries.len(), 1);
    }
}
