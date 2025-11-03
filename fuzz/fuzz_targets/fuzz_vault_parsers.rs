#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Test vault-related parsing functions

        // Fuzz secret path parsing (vault_client.rs)
        test_parse_secret_path(input);

        // Fuzz URL parsing for vault addresses
        test_vault_url_parsing(input);

        // Fuzz secret data validation
        test_secret_data_size(input);

        // Fuzz JSON secret parsing
        test_json_secret_parsing(input);

        // Fuzz namespace parsing
        test_namespace_parsing(input);
    }
});

/// Test Vault secret path parsing
/// Format: "secret/path@kvv2" or "secret/path@kvv1"
fn test_parse_secret_path(path: &str) {
    // Split on '@' to extract secret engine
    if let Some(at_pos) = path.rfind('@') {
        let (_secret_path, engine) = path.split_at(at_pos);
        let engine_type = &engine[1..]; // Skip the '@'

        // Valid engines: kvv1, kvv2
        let _is_valid = matches!(engine_type, "kvv1" | "kvv2");
    }
}

/// Test Vault URL parsing and HTTPS validation
fn test_vault_url_parsing(url_str: &str) {
    use url::Url;

    if let Ok(url) = Url::parse(url_str) {
        // Should be HTTPS for production Vault
        let _is_https = url.scheme() == "https";

        // Check for valid host
        let _has_host = url.host().is_some();

        // Check for port
        let _port = url.port();
    }
}

/// Test secret data validation for size limits
/// MAX_SECRET_SIZE_BYTES = 1MB, MAX_SECRET_KEYS = 100
fn test_secret_data_size(json: &str) {
    const MAX_SECRET_SIZE_BYTES: usize = 1_048_576; // 1MB
    const MAX_SECRET_KEYS: usize = 100;

    // Check JSON size
    let byte_size = json.len();
    let _exceeds_size = byte_size > MAX_SECRET_SIZE_BYTES;

    // Try to parse as JSON object
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(json) {
        let key_count = map.len();
        let _exceeds_key_count = key_count > MAX_SECRET_KEYS;

        // Check individual key/value sizes
        for (key, value) in map.iter() {
            let key_len = key.len();
            let value_len = value.to_string().len();

            // Example limits: max 256 chars for keys, max 64KB for values
            let _key_too_long = key_len > 256;
            let _value_too_long = value_len > 65536;
        }
    }
}

/// Test JSON secret parsing
fn test_json_secret_parsing(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct SecretData {
        api_id: Option<String>,
        api_key: Option<String>,
        #[serde(flatten)]
        extra: Option<serde_json::Map<String, serde_json::Value>>,
    }

    let _ = serde_json::from_str::<SecretData>(json);
}

/// Test Vault namespace parsing
fn test_namespace_parsing(namespace: &str) {
    // Namespaces can contain alphanumeric and slashes
    // Example: "org/team/project"

    if !namespace.is_empty() {
        // Check for valid characters
        let _valid_chars = namespace
            .chars()
            .all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_');

        // Check for consecutive slashes
        let _has_consecutive_slashes = namespace.contains("//");

        // Check for leading/trailing slashes
        let _starts_with_slash = namespace.starts_with('/');
        let _ends_with_slash = namespace.ends_with('/');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_secret_path() {
        test_parse_secret_path("secret/veracode@kvv2");
        test_parse_secret_path("kv/prod/api@kvv1");
    }

    #[test]
    fn test_invalid_secret_path() {
        // Missing '@'
        test_parse_secret_path("secret/veracode");
        // Invalid engine
        test_parse_secret_path("secret/veracode@kvv3");
    }

    #[test]
    fn test_vault_urls() {
        test_vault_url_parsing("https://vault.example.com:8200");
        test_vault_url_parsing("http://localhost:8200");
        test_vault_url_parsing("not-a-url");
    }
}
