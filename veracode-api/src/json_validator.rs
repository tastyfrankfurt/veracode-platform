//! JSON validation utilities to prevent DoS attacks
//!
//! This module provides functions to validate JSON structure before deserialization,
//! preventing Denial of Service attacks through deeply nested JSON structures.

use serde_json::Value;

/// Maximum allowed JSON nesting depth
///
/// This limit prevents DoS attacks via deeply nested JSON that can cause:
/// - Stack overflow
/// - Excessive memory consumption
/// - CPU exhaustion during parsing
///
/// A depth of 32 is sufficient for legitimate API responses while protecting
/// against malicious payloads. Most real-world APIs use <10 levels of nesting.
pub const MAX_JSON_DEPTH: usize = 32;

/// Validate JSON nesting depth to prevent DoS attacks
///
/// # Arguments
///
/// * `json_str` - The JSON string to validate
/// * `max_depth` - Maximum allowed nesting depth (use `MAX_JSON_DEPTH` for default)
///
/// # Returns
///
/// * `Ok(())` if the JSON is valid and within depth limits
/// * `Err(String)` with error message if validation fails
///
/// # Examples
///
/// ```
/// use veracode_platform::json_validator::{validate_json_depth, MAX_JSON_DEPTH};
///
/// // Valid JSON within depth limit
/// let json = r#"{"user": {"profile": {"settings": {"theme": "dark"}}}}"#;
/// assert!(validate_json_depth(json, MAX_JSON_DEPTH).is_ok());
///
/// // Deeply nested JSON should be rejected
/// let deep_json = (0..50).fold(String::from("{\"a\":"), |acc, _| acc + "{\"a\":")
///     + &(0..50).map(|_| "}").collect::<String>();
/// assert!(validate_json_depth(&deep_json, MAX_JSON_DEPTH).is_err());
/// ```
///
/// # Security
///
/// This function protects against:
/// - Stack overflow from recursive parsing
/// - CPU exhaustion from excessive nesting
/// - Memory exhaustion from deeply nested structures
pub fn validate_json_depth(json_str: &str, max_depth: usize) -> Result<(), String> {
    // First, try to parse the JSON
    let value: Value =
        serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {}", e))?;

    // Calculate the actual nesting depth
    let depth = calculate_depth(&value);

    if depth > max_depth {
        return Err(format!(
            "JSON nesting depth {} exceeds maximum allowed depth of {}",
            depth, max_depth
        ));
    }

    Ok(())
}

/// Calculate the maximum nesting depth of a JSON value
///
/// # Arguments
///
/// * `value` - The JSON value to analyze
///
/// # Returns
///
/// The maximum nesting depth (0 for scalars, 1+ for nested structures)
fn calculate_depth(value: &Value) -> usize {
    match value {
        Value::Array(arr) => {
            if arr.is_empty() {
                1
            } else {
                1_usize.saturating_add(arr.iter().map(calculate_depth).max().unwrap_or(0))
            }
        }
        Value::Object(obj) => {
            if obj.is_empty() {
                1
            } else {
                1_usize.saturating_add(obj.values().map(calculate_depth).max().unwrap_or(0))
            }
        }
        // Scalars have depth 0
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 0,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_depth_scalar() {
        let value = serde_json::json!("test");
        assert_eq!(calculate_depth(&value), 0);

        let value = serde_json::json!(42);
        assert_eq!(calculate_depth(&value), 0);

        let value = serde_json::json!(true);
        assert_eq!(calculate_depth(&value), 0);

        let value = serde_json::json!(null);
        assert_eq!(calculate_depth(&value), 0);
    }

    #[test]
    fn test_calculate_depth_simple_object() {
        let value = serde_json::json!({"key": "value"});
        assert_eq!(calculate_depth(&value), 1);
    }

    #[test]
    fn test_calculate_depth_simple_array() {
        let value = serde_json::json!([1, 2, 3]);
        assert_eq!(calculate_depth(&value), 1);
    }

    #[test]
    fn test_calculate_depth_nested_object() {
        let value = serde_json::json!({
            "user": {
                "profile": {
                    "settings": {
                        "theme": "dark"
                    }
                }
            }
        });
        assert_eq!(calculate_depth(&value), 4);
    }

    #[test]
    fn test_calculate_depth_nested_array() {
        let value = serde_json::json!([[[1, 2], [3, 4]]]);
        assert_eq!(calculate_depth(&value), 3);
    }

    #[test]
    fn test_calculate_depth_mixed() {
        let value = serde_json::json!({
            "data": [
                {"nested": [1, 2, 3]},
                {"nested": [4, 5, 6]}
            ]
        });
        // Depth: root object (1) + array (1) + inner objects (1) + inner arrays (1) = 4
        assert_eq!(calculate_depth(&value), 4);
    }

    #[test]
    fn test_calculate_depth_empty_structures() {
        let value = serde_json::json!({});
        assert_eq!(calculate_depth(&value), 1);

        let value = serde_json::json!([]);
        assert_eq!(calculate_depth(&value), 1);
    }

    #[test]
    fn test_validate_json_depth_valid() {
        let json = r#"{"user": {"profile": {"name": "test"}}}"#;
        assert!(validate_json_depth(json, MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn test_validate_json_depth_at_limit() {
        // Create JSON at exactly MAX_JSON_DEPTH
        let mut json = String::from("{");
        for i in 0..MAX_JSON_DEPTH - 1 {
            json.push_str(&format!("\"level{}\":{{", i));
        }
        json.push_str("\"value\":42");
        json.push_str(&"}".repeat(MAX_JSON_DEPTH));

        assert!(validate_json_depth(&json, MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn test_validate_json_depth_exceeds_limit() {
        // Create JSON that exceeds MAX_JSON_DEPTH
        let mut json = String::from("{");
        for i in 0..MAX_JSON_DEPTH + 5 {
            json.push_str(&format!("\"level{}\":{{", i));
        }
        json.push_str("\"value\":42");
        json.push_str(&"}".repeat(MAX_JSON_DEPTH + 6));

        let result = validate_json_depth(&json, MAX_JSON_DEPTH);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail on deeply nested json")
                .contains("exceeds maximum allowed depth")
        );
    }

    #[test]
    fn test_validate_json_depth_invalid_json() {
        let json = r#"{"invalid": json}"#;
        let result = validate_json_depth(json, MAX_JSON_DEPTH);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail on invalid json")
                .contains("Invalid JSON")
        );
    }

    #[test]
    fn test_validate_json_depth_deeply_nested_array() {
        // Create deeply nested array
        let mut json = String::new();
        for _ in 0..50 {
            json.push('[');
        }
        json.push_str("42");
        for _ in 0..50 {
            json.push(']');
        }

        let result = validate_json_depth(&json, MAX_JSON_DEPTH);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail on deeply nested json")
                .contains("exceeds maximum allowed depth")
        );
    }

    #[test]
    fn test_validate_json_depth_custom_limit() {
        let json = r#"{"a": {"b": {"c": {"d": "value"}}}}"#;

        // Should pass with limit 5
        assert!(validate_json_depth(json, 5).is_ok());

        // Should fail with limit 3
        let result = validate_json_depth(json, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_realistic_api_response() {
        // Simulate a realistic API response with moderate nesting
        let json = r#"{
            "_embedded": {
                "applications": [
                    {
                        "id": 123,
                        "profile": {
                            "name": "TestApp",
                            "settings": {
                                "scan": {
                                    "enabled": true
                                }
                            }
                        }
                    }
                ]
            }
        }"#;

        assert!(validate_json_depth(json, MAX_JSON_DEPTH).is_ok());
    }

    #[test]
    fn test_dos_payload_detection() {
        // Test case similar to what a fuzzer might generate
        // This creates a very deeply nested structure that could cause DoS
        let depth = 100;
        let mut json = String::new();

        // Create nested objects
        for i in 0..depth {
            json.push_str(&format!("{{\"level_{}\":", i));
        }
        json.push_str("null");
        for _ in 0..depth {
            json.push('}');
        }

        let result = validate_json_depth(&json, MAX_JSON_DEPTH);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should fail on deeply nested json")
                .contains("exceeds maximum allowed depth")
        );
    }
}
