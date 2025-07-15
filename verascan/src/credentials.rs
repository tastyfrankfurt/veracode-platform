use crate::cli::Args;

/// Secure wrapper for API credentials that prevents exposure in debug output
#[derive(Clone)]
pub struct SecureApiCredentials {
    pub api_id: Option<SecureApiId>,
    pub api_key: Option<SecureApiKey>,
}

/// Secure wrapper for API ID that redacts the value in debug output
#[derive(Clone)]
pub struct SecureApiId(String);

/// Secure wrapper for API Key that redacts the value in debug output
#[derive(Clone)]
pub struct SecureApiKey(String);

impl SecureApiId {
    pub fn new(api_id: String) -> Self {
        SecureApiId(api_id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl SecureApiKey {
    pub fn new(api_key: String) -> Self {
        SecureApiKey(api_key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for SecureApiId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Debug for SecureApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Debug for SecureApiCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureApiCredentials")
            .field("api_id", &self.api_id)
            .field("api_key", &self.api_key)
            .finish()
    }
}

impl SecureApiCredentials {
    pub fn new(api_id: Option<String>, api_key: Option<String>) -> Self {
        Self {
            api_id: api_id.map(SecureApiId::new),
            api_key: api_key.map(SecureApiKey::new),
        }
    }

    pub fn extract_credentials(&self) -> Result<(String, String), ()> {
        match (&self.api_id, &self.api_key) {
            (Some(id), Some(key)) => Ok((id.as_str().to_string(), key.as_str().to_string())),
            _ => {
                eprintln!("❌ Pipeline scan requires Veracode API credentials");
                eprintln!("💡 Set VERACODE_API_ID and VERACODE_API_KEY environment variables");
                eprintln!("💡 API credentials must contain only alphanumeric characters");
                Err(())
            }
        }
    }
}

pub fn validate_api_credential(value: &str, field_name: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} cannot be empty", field_name));
    }

    if !value.chars().all(|c| c.is_alphanumeric()) {
        return Err(format!(
            "{} must contain only alphanumeric characters",
            field_name
        ));
    }

    Ok(())
}

pub fn load_api_credentials(args: &mut Args) -> Result<(), i32> {
    args.api_id = match std::env::var("VERACODE_API_ID") {
        Ok(id) => {
            if let Err(e) = validate_api_credential(&id, "VERACODE_API_ID") {
                eprintln!("❌ Invalid VERACODE_API_ID: {}", e);
                return Err(1);
            }
            Some(id)
        }
        Err(_) => None,
    };

    args.api_key = match std::env::var("VERACODE_API_KEY") {
        Ok(key) => {
            if let Err(e) = validate_api_credential(&key, "VERACODE_API_KEY") {
                eprintln!("❌ Invalid VERACODE_API_KEY: {}", e);
                return Err(1);
            }
            Some(key)
        }
        Err(_) => None,
    };

    Ok(())
}

/// Load API credentials into a secure wrapper
pub fn load_secure_api_credentials() -> Result<SecureApiCredentials, i32> {
    let api_id = match std::env::var("VERACODE_API_ID") {
        Ok(id) => {
            if let Err(e) = validate_api_credential(&id, "VERACODE_API_ID") {
                eprintln!("❌ Invalid VERACODE_API_ID: {}", e);
                return Err(1);
            }
            Some(id)
        }
        Err(_) => None,
    };

    let api_key = match std::env::var("VERACODE_API_KEY") {
        Ok(key) => {
            if let Err(e) = validate_api_credential(&key, "VERACODE_API_KEY") {
                eprintln!("❌ Invalid VERACODE_API_KEY: {}", e);
                return Err(1);
            }
            Some(key)
        }
        Err(_) => None,
    };

    Ok(SecureApiCredentials::new(api_id, api_key))
}

pub fn check_pipeline_credentials(args: &Args) -> Result<(String, String), ()> {
    match (&args.api_id, &args.api_key) {
        (Some(id), Some(key)) => Ok((id.clone(), key.clone())),
        _ => {
            eprintln!("❌ Pipeline scan requires Veracode API credentials");
            eprintln!("💡 Set VERACODE_API_ID and VERACODE_API_KEY environment variables");
            eprintln!("💡 API credentials must contain only alphanumeric characters");
            Err(())
        }
    }
}

/// Check pipeline credentials using secure wrapper
pub fn check_secure_pipeline_credentials(
    secure_creds: &SecureApiCredentials,
) -> Result<(String, String), ()> {
    secure_creds.extract_credentials()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_api_id_debug_redaction() {
        let api_id = SecureApiId::new("test_api_id_123".to_string());
        let debug_output = format!("{:?}", api_id);
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("test_api_id_123"));
    }

    #[test]
    fn test_secure_api_key_debug_redaction() {
        let api_key = SecureApiKey::new("test_api_key_456".to_string());
        let debug_output = format!("{:?}", api_key);
        assert_eq!(debug_output, "[REDACTED]");
        assert!(!debug_output.contains("test_api_key_456"));
    }

    #[test]
    fn test_secure_api_credentials_debug_redaction() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );
        let debug_output = format!("{:?}", creds);

        // Should show structure but redact actual values
        assert!(debug_output.contains("SecureApiCredentials"));
        assert!(debug_output.contains("api_id"));
        assert!(debug_output.contains("api_key"));
        assert!(debug_output.contains("[REDACTED]"));

        // Should not contain actual credential values
        assert!(!debug_output.contains("test_api_id_123"));
        assert!(!debug_output.contains("test_api_key_456"));
    }

    #[test]
    fn test_secure_api_id_access_methods() {
        let api_id = SecureApiId::new("test_api_id_123".to_string());

        // Test as_str method
        assert_eq!(api_id.as_str(), "test_api_id_123");

        // Test into_string method
        let string_value = api_id.into_string();
        assert_eq!(string_value, "test_api_id_123");
    }

    #[test]
    fn test_secure_api_key_access_methods() {
        let api_key = SecureApiKey::new("test_api_key_456".to_string());

        // Test as_str method
        assert_eq!(api_key.as_str(), "test_api_key_456");

        // Test into_string method
        let string_value = api_key.into_string();
        assert_eq!(string_value, "test_api_key_456");
    }

    #[test]
    fn test_secure_api_credentials_extract_success() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );

        let result = creds.extract_credentials();
        assert!(result.is_ok());

        let (id, key) = result.unwrap();
        assert_eq!(id, "test_api_id_123");
        assert_eq!(key, "test_api_key_456");
    }

    #[test]
    fn test_secure_api_credentials_extract_missing_id() {
        let creds = SecureApiCredentials::new(None, Some("test_api_key_456".to_string()));

        let result = creds.extract_credentials();
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_api_credentials_extract_missing_key() {
        let creds = SecureApiCredentials::new(Some("test_api_id_123".to_string()), None);

        let result = creds.extract_credentials();
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_api_credentials_extract_missing_both() {
        let creds = SecureApiCredentials::new(None, None);

        let result = creds.extract_credentials();
        assert!(result.is_err());
    }

    #[test]
    fn test_check_secure_pipeline_credentials_success() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );

        let result = check_secure_pipeline_credentials(&creds);
        assert!(result.is_ok());

        let (id, key) = result.unwrap();
        assert_eq!(id, "test_api_id_123");
        assert_eq!(key, "test_api_key_456");
    }

    #[test]
    fn test_check_secure_pipeline_credentials_failure() {
        let creds = SecureApiCredentials::new(None, None);

        let result = check_secure_pipeline_credentials(&creds);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_api_credentials_clone() {
        let creds = SecureApiCredentials::new(
            Some("test_api_id_123".to_string()),
            Some("test_api_key_456".to_string()),
        );

        let cloned_creds = creds.clone();

        // Both should extract the same credentials
        let original_result = creds.extract_credentials().unwrap();
        let cloned_result = cloned_creds.extract_credentials().unwrap();

        assert_eq!(original_result, cloned_result);
    }
}
