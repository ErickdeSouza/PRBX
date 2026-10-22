pub struct JniReport<'a> {
    pub has_on_load: bool,
    pub java_exports: Vec<JavaExport<'a>>,
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
}
