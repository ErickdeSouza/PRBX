use crate::{analysis::dex::NativeMethod, apk::NativeLibrary};

pub struct JniReport<'a> {
    pub has_on_load: bool,
    pub java_exports: Vec<JavaExport<'a>>,
}

pub struct NativeMethodResolution {
    pub class_name: String,
    pub method_name: String,
    pub parameter_descriptor: String,
    pub dex_file: String,
    pub resolution: NativeResolutionKind,
    pub matching_exports: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeResolutionKind {
    ExactSignature,
    ShortName,
    AmbiguousShortName,
    Unmatched,
}

pub struct NativeLinkReport {
    pub methods: Vec<NativeMethodResolution>,
    pub conventional_matches: usize,
    pub exact_signature_matches: usize,
    pub ambiguous_short_names: usize,
    pub without_conventional_match: usize,
    pub on_load_libraries: Vec<String>,
}

pub struct JavaExport<'a> {
    pub symbol: &'a str,
    pub method: Option<String>,
    pub parameter_descriptor: Option<String>,
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
            parameter_descriptor: decode_native_export(symbol)
                .and_then(|(_, descriptor)| descriptor),
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
            let Some((method, parameter_descriptor)) = decode_native_export(export.symbol) else {
                continue;
            };
            let Some((class_name, method_name)) = method.rsplit_once('.') else {
                continue;
            };
            exports_by_method.push((
                class_name.replace('/', "."),
                method_name.to_owned(),
                parameter_descriptor,
                format!("{}:{} ({})", library.path, export.symbol, library.abi),
            ));
        }
    }

    let mut conventional_matches = 0;
    let mut exact_signature_matches = 0;
    let mut ambiguous_short_names = 0;
    let mut resolutions = Vec::with_capacity(methods.len());
    for method in methods {
        let same_name_methods = methods
            .iter()
            .filter(|candidate| {
                candidate.class_name == method.class_name
                    && candidate.method_name == method.method_name
            })
            .count();
        let exact_matches = exports_by_method
            .iter()
            .filter(|(class, name, descriptor, _)| {
                class == &method.class_name
                    && name == &method.method_name
                    && descriptor.as_deref() == Some(method.parameter_descriptor.as_str())
            })
            .map(|(_, _, _, export)| export.clone())
            .collect::<Vec<_>>();
        let (resolution, matching_exports) = if !exact_matches.is_empty() {
            conventional_matches += 1;
            exact_signature_matches += 1;
            (NativeResolutionKind::ExactSignature, exact_matches)
        } else {
            let short_matches = exports_by_method
                .iter()
                .filter(|(class, name, descriptor, _)| {
                    class == &method.class_name
                        && name == &method.method_name
                        && descriptor.is_none()
                })
                .map(|(_, _, _, export)| export.clone())
                .collect::<Vec<_>>();
            if short_matches.is_empty() {
                (NativeResolutionKind::Unmatched, Vec::new())
            } else if same_name_methods == 1 {
                conventional_matches += 1;
                (NativeResolutionKind::ShortName, short_matches)
            } else {
                ambiguous_short_names += 1;
                (NativeResolutionKind::AmbiguousShortName, short_matches)
            }
        };
        resolutions.push(NativeMethodResolution {
            class_name: method.class_name.clone(),
            method_name: method.method_name.clone(),
            parameter_descriptor: method.parameter_descriptor.clone(),
            dex_file: method.dex_file.clone(),
            resolution,
            matching_exports,
        });
    }
    on_load_libraries.sort();
    NativeLinkReport {
        without_conventional_match: resolutions
            .iter()
            .filter(|resolution| resolution.resolution == NativeResolutionKind::Unmatched)
            .count(),
        methods: resolutions,
        conventional_matches,
        exact_signature_matches,
        ambiguous_short_names,
        on_load_libraries,
    }
}

fn decode_native_export(symbol: &str) -> Option<(String, Option<String>)> {
    let encoded = symbol.strip_prefix("Java_")?;
    let (encoded_name, encoded_signature) = encoded
        .split_once("__")
        .map_or((encoded, None), |(name, signature)| (name, Some(signature)));
    let separator = encoded_name
        .char_indices()
        .rev()
        .find_map(|(index, character)| {
            if character != '_' {
                return None;
            }
            let next = encoded_name[index + 1..].chars().next()?;
            (!matches!(next, '0' | '1' | '2' | '3')).then_some(index)
        })?;
    let (class, method) = encoded_name.split_at(separator);
    let method = method.strip_prefix('_')?;
    let decoded_name = format!(
        "{}.{}",
        decode_jni_name(class, true)?,
        decode_jni_name(method, false)?
    );
    let parameter_descriptor = match encoded_signature {
        Some(signature) => Some(decode_jni_signature(signature)?),
        None => None,
    };
    Some((decoded_name, parameter_descriptor))
}

fn decode_native_method(symbol: &str) -> Option<String> {
    decode_native_export(symbol).map(|(method, _)| method)
}

fn decode_jni_signature(encoded: &str) -> Option<String> {
    let mut decoded = String::new();
    let mut chars = encoded.chars().peekable();
    decoded.push('(');
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
                decoded.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
            }
            _ => decoded.push('/'),
        }
    }
    decoded.push(')');
    Some(decoded)
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
            parameter_descriptor: "()".to_owned(),
            dex_file: "classes.dex".to_owned(),
        }
    }

    fn native_method_with_parameters(
        class_name: &str,
        method_name: &str,
        parameter_descriptor: &str,
    ) -> NativeMethod {
        NativeMethod {
            class_name: class_name.to_owned(),
            method_name: method_name.to_owned(),
            parameter_descriptor: parameter_descriptor.to_owned(),
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
        assert_eq!(
            decode_native_export("Java_com_example_Native_native_1init__ILjava_lang_String_2"),
            Some((
                "com/example/Native.native_init".to_owned(),
                Some("(ILjava/lang/String;)".to_owned())
            ))
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
        assert_eq!(report.exact_signature_matches, 0);
        assert_eq!(report.without_conventional_match, 1);
        assert_eq!(report.methods[0].matching_exports.len(), 1);
        assert_eq!(
            report.methods[0].resolution,
            NativeResolutionKind::ShortName
        );
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
            native_method_with_parameters("com.example.Native", "native_init", "(I)"),
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

    #[test]
    fn resolves_overloaded_methods_by_full_parameter_descriptor() {
        let methods = vec![
            native_method_with_parameters("com.example.Native", "convert", "(I)"),
            native_method_with_parameters("com.example.Native", "convert", "(Ljava/lang/String;)"),
        ];
        let libraries = vec![library(
            "lib/arm64-v8a/libnative.so",
            &[
                "Java_com_example_Native_convert__I",
                "Java_com_example_Native_convert__Ljava_lang_String_2",
            ],
        )];

        let report = resolve_native_methods(&methods, &libraries);
        assert_eq!(report.exact_signature_matches, 2);
        assert_eq!(report.conventional_matches, 2);
        assert!(
            report
                .methods
                .iter()
                .all(|method| method.resolution == NativeResolutionKind::ExactSignature)
        );
        assert!(
            report
                .methods
                .iter()
                .all(|method| method.matching_exports.len() == 1)
        );
    }

    #[test]
    fn flags_short_jni_export_as_ambiguous_for_overloaded_methods() {
        let methods = vec![
            native_method_with_parameters("com.example.Native", "convert", "(I)"),
            native_method_with_parameters("com.example.Native", "convert", "(J)"),
        ];
        let libraries = vec![library(
            "lib/arm64-v8a/libnative.so",
            &["Java_com_example_Native_convert"],
        )];

        let report = resolve_native_methods(&methods, &libraries);
        assert_eq!(report.conventional_matches, 0);
        assert_eq!(report.ambiguous_short_names, 2);
        assert!(
            report
                .methods
                .iter()
                .all(|method| method.resolution == NativeResolutionKind::AmbiguousShortName)
        );
    }
}
