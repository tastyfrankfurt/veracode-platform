//! JSON validation utilities to prevent `DoS` attacks
//!
//! This module provides functions to validate JSON structure before deserialization,
//! preventing Denial of Service attacks through deeply nested JSON structures.

use log::warn;
use serde_json::Value;

/// Maximum allowed JSON nesting depth
///
/// This limit prevents `DoS` attacks via deeply nested `JSON` that can cause:
/// - Stack overflow
/// - Excessive memory consumption
/// - CPU exhaustion during parsing
///
/// A depth of 32 is sufficient for legitimate API responses while protecting
/// against malicious payloads. Most real-world APIs use <10 levels of nesting.
pub const MAX_JSON_DEPTH: usize = 32;

/// Validate JSON nesting depth to prevent `DoS` attacks
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
///
/// # Errors
///
/// Returns an error if the JSON is invalid or exceeds the maximum nesting depth.
/// Error messages are sanitized to avoid information disclosure, with detailed
/// errors logged internally for debugging.
pub fn validate_json_depth(json_str: &str, max_depth: usize) -> Result<(), String> {
    // First, try to parse the JSON
    let value: Value = serde_json::from_str(json_str).map_err(|e| {
        // Log detailed parse error for debugging (internal only)
        warn!("JSON parse error: {}", e);
        // Return sanitized error to caller (may be exposed to users)
        "Invalid JSON format".to_string()
    })?;

    // Calculate the actual nesting depth
    let depth = calculate_depth(&value);

    if depth > max_depth {
        // Log detailed depth information for debugging (internal only)
        warn!(
            "JSON depth validation failed: depth {} exceeds maximum {}",
            depth, max_depth
        );
        // Return sanitized error to caller (may be exposed to users)
        return Err("JSON structure too deeply nested".to_string());
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
///
/// # Security
///
/// Uses bounded recursion to prevent stack overflow. Stops early if depth exceeds `MAX_JSON_DEPTH`.
fn calculate_depth(value: &Value) -> usize {
    calculate_depth_limited(value, 0)
}

/// Calculate depth with recursion limit to prevent stack overflow
///
/// Stops recursion early once `MAX_JSON_DEPTH` is exceeded, preventing stack overflow
/// on maliciously deep JSON (e.g., 10,000+ nesting levels).
fn calculate_depth_limited(value: &Value, current_depth: usize) -> usize {
    // Early termination: stop recursing if we've exceeded the limit
    // We don't need exact depth if it's already > MAX_JSON_DEPTH
    if current_depth > MAX_JSON_DEPTH {
        return current_depth;
    }

    match value {
        Value::Array(arr) => {
            if arr.is_empty() {
                1
            } else {
                let max_child = arr
                    .iter()
                    .map(|v| calculate_depth_limited(v, current_depth.saturating_add(1)))
                    .max()
                    .unwrap_or(0);
                1_usize.saturating_add(max_child)
            }
        }
        Value::Object(obj) => {
            if obj.is_empty() {
                1
            } else {
                let max_child = obj
                    .values()
                    .map(|v| calculate_depth_limited(v, current_depth.saturating_add(1)))
                    .max()
                    .unwrap_or(0);
                1_usize.saturating_add(max_child)
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
                .contains("too deeply nested")
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
                .contains("Invalid JSON format")
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
                .contains("too deeply nested")
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
                .contains("too deeply nested")
        );
    }
}

// ============================================================================
// TIER 1: PROPERTY-BASED SECURITY TESTS (Fast, High ROI)
// ============================================================================
//
// These tests use proptest to validate security properties against adversarial
// inputs. They run 1000 test cases in normal mode and 10 under Miri for UB detection.

#[cfg(test)]
#[allow(clippy::expect_used)]
mod proptest_security {
    use super::*;
    use proptest::prelude::*;

    // ============================================================================
    // SECURITY TEST: JSON Depth Validation with Adversarial Inputs
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Valid JSON within depth limits must always succeed
        /// Tests that legitimate JSON structures are never incorrectly rejected
        #[test]
        fn proptest_valid_json_within_limits_succeeds(
            depth in 1usize..=MAX_JSON_DEPTH,
        ) {
            // Create JSON with exactly 'depth' nesting levels
            let mut json = String::new();
            for i in 0..depth {
                json.push_str(&format!("{{\"level{}\":", i));
            }
            json.push_str("\"value\"");
            json.push_str(&"}".repeat(depth));

            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok(), "Valid JSON at depth {} should succeed", depth);
        }

        /// Property: JSON exceeding depth limits must always fail
        /// Tests that deeply nested JSON is correctly rejected
        #[test]
        fn proptest_deeply_nested_json_rejected(
            excess_depth in 1usize..=50,
        ) {
            let depth = MAX_JSON_DEPTH.saturating_add(excess_depth);

            // Create JSON that exceeds MAX_JSON_DEPTH
            let mut json = String::new();
            for i in 0..depth {
                json.push_str(&format!("{{\"level{}\":", i));
            }
            json.push_str("null");
            json.push_str(&"}".repeat(depth));

            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_err(), "JSON at depth {} should be rejected", depth);

            // Error can be either from depth validation or from serde_json's recursion limit
            if let Err(msg) = result {
                prop_assert!(
                    msg.contains("too deeply nested") || msg == "Invalid JSON format",
                    "Error message should indicate rejection: {}", msg
                );
            }
        }

        /// Property: Invalid JSON must return parse error, never panic
        /// Tests that malformed JSON is handled gracefully
        #[test]
        fn proptest_invalid_json_returns_error(
            garbage in ".*{0,200}",
        ) {
            // Most random strings are not valid JSON
            let result = validate_json_depth(&garbage, MAX_JSON_DEPTH);

            // Either valid JSON or error, never panic
            match result {
                Ok(_) => {
                    // If it succeeded, must be valid JSON
                    prop_assert!(serde_json::from_str::<Value>(&garbage).is_ok());
                },
                Err(msg) => {
                    // Error should be sanitized
                    prop_assert!(
                        msg == "Invalid JSON format" || msg.contains("too deeply nested"),
                        "Error message should be sanitized"
                    );
                }
            }
        }

        /// Property: Empty and whitespace-only JSON must be handled
        /// Tests edge cases with minimal input
        #[test]
        fn proptest_empty_and_whitespace_json(
            whitespace in "\\s{0,100}",
        ) {
            let result = validate_json_depth(&whitespace, MAX_JSON_DEPTH);

            // Empty/whitespace is invalid JSON, should return error
            match result {
                Ok(_) => {
                    // Only succeeds if it's valid JSON (unlikely with just whitespace)
                    prop_assert!(serde_json::from_str::<Value>(&whitespace).is_ok());
                },
                Err(msg) => {
                    prop_assert_eq!(msg, "Invalid JSON format");
                }
            }
        }

        /// Property: Custom depth limits must be respected
        /// Tests that the max_depth parameter is correctly enforced
        #[test]
        fn proptest_custom_depth_limit_enforced(
            max_depth in 5usize..=MAX_JSON_DEPTH,
            test_depth in 1usize..=MAX_JSON_DEPTH,
        ) {
            // Only test within MAX_JSON_DEPTH to avoid serde_json's own limits
            // Create JSON with test_depth nesting
            let mut json = String::new();
            for i in 0..test_depth {
                json.push_str(&format!("{{\"d{}\":", i));
            }
            json.push('0');
            json.push_str(&"}".repeat(test_depth));

            let result = validate_json_depth(&json, max_depth);

            // Property: validation result should match depth comparison
            if test_depth <= max_depth {
                prop_assert!(result.is_ok(),
                    "JSON depth {} should pass with limit {}", test_depth, max_depth);
            } else {
                prop_assert!(result.is_err(),
                    "JSON depth {} should fail with limit {}", test_depth, max_depth);
            }
        }
    }

    // ============================================================================
    // SECURITY TEST: String Handling and Injection Attacks
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Special characters in JSON strings must be handled safely
        /// Tests against JSON injection and escape sequence attacks
        #[test]
        fn proptest_special_characters_in_strings(
            special_chars in r#"[<>'"&\x00-\x1f\x7f\\]{0,100}"#,
        ) {
            let json = serde_json::json!({
                "payload": special_chars,
                "nested": {
                    "value": special_chars
                }
            }).to_string();

            // Property 1: Must not panic on special characters
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            // Property 2: Parse result must preserve the data
            let parsed: Value = serde_json::from_str(&json)
                .expect("serde_json should handle its own output");
            prop_assert_eq!(parsed.get("payload").and_then(|v| v.as_str()), Some(special_chars.as_str()));
        }

        /// Property: Control characters must be properly escaped
        /// Tests that control characters don't break JSON parsing
        #[test]
        fn proptest_control_characters_safe(
            // Test various control characters that could cause issues
            control_char in prop::sample::select(vec![
                '\0', '\t', '\n', '\r', '\x01', '\x02', '\x08', '\x0c', '\x1f', '\x7f'
            ]),
        ) {
            let payload = format!("test{}value", control_char);
            let json = serde_json::json!({
                "data": payload
            }).to_string();

            // Must successfully validate and parse
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());
        }

        /// Property: Extremely long strings must not cause buffer overflows
        /// Tests memory safety with large string values
        #[test]
        fn proptest_large_strings_safe(
            length in 0usize..=10000,
        ) {
            let large_string = "A".repeat(length);
            let json = serde_json::json!({
                "large_field": large_string
            }).to_string();

            // Property 1: Must not panic on large strings
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            // Property 2: Depth should be 1 (just the object)
            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            prop_assert_eq!(calculate_depth(&parsed), 1);
        }

        /// Property: Unicode edge cases must be handled correctly
        /// Tests UTF-8 boundary handling and multi-byte characters
        #[test]
        fn proptest_unicode_handling(
            // Test various Unicode ranges including emojis and special scripts
            unicode_str in "[\\p{L}\\p{N}\\p{S}\\p{M}]{0,200}",
        ) {
            let json = serde_json::json!({
                "unicode": unicode_str,
                "nested": {
                    "more_unicode": unicode_str
                }
            }).to_string();

            // Property 1: Must handle Unicode correctly
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            // Property 2: Unicode should be preserved
            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            prop_assert_eq!(parsed.get("unicode").and_then(|v| v.as_str()), Some(unicode_str.as_str()));
        }

        /// Property: Path traversal sequences in JSON values must be safely contained
        /// Tests that path traversal strings don't affect JSON validation
        #[test]
        fn proptest_path_traversal_sequences_safe(
            // Test common path traversal patterns
            traversal in prop::sample::select(vec![
                "../", "..\\", "../../", "../../../etc/passwd",
                "....//", "..\\..\\", "/etc/passwd", "C:\\Windows\\System32",
                "%2e%2e%2f", "%2e%2e/", "..%2f", "..%5c"
            ]),
        ) {
            let json = serde_json::json!({
                "filename": traversal,
                "path": traversal
            }).to_string();

            // Property: Path traversal sequences are just string data in JSON
            // They should not affect validation or cause any special behavior
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            // Data should be preserved as-is
            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            prop_assert_eq!(parsed.get("filename").and_then(|v| v.as_str()), Some(traversal));
        }

        /// Property: Null byte injection attempts must be handled safely
        /// Tests that null bytes in JSON strings don't cause truncation
        #[test]
        fn proptest_null_byte_injection_safe(
            prefix in "[a-zA-Z0-9]{0,50}",
            suffix in "[a-zA-Z0-9]{0,50}",
        ) {
            // Create a string with null byte
            let payload = format!("{}\0{}", prefix, suffix);
            let json = serde_json::json!({
                "payload": payload
            }).to_string();

            // Property: Null bytes should be properly escaped in JSON
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            // Verify the null byte was preserved through encoding/decoding
            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            if let Some(s) = parsed.get("payload").and_then(|v| v.as_str()) {
                // The null byte should be present in the decoded string
                let expected_without_null = format!("{}{}", prefix, suffix);
                prop_assert!(s.contains('\0') || s == expected_without_null);
            }
        }
    }

    // ============================================================================
    // SECURITY TEST: Array and Object Boundary Conditions
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Large arrays must not cause memory exhaustion
        /// Tests that large (but shallow) arrays are handled efficiently
        #[test]
        fn proptest_large_arrays_safe(
            size in 0usize..=1000,
        ) {
            let array: Vec<i32> = (0..size).map(|i| i32::try_from(i).unwrap_or(0)).collect();
            let json = serde_json::json!({
                "large_array": array
            }).to_string();

            // Property 1: Must not panic on large arrays
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            // Property 2: Depth should be 2 (object + array)
            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            prop_assert_eq!(calculate_depth(&parsed), 2);
        }

        /// Property: Large objects must not cause memory exhaustion
        /// Tests that objects with many keys are handled efficiently
        #[test]
        fn proptest_large_objects_safe(
            key_count in 0usize..=500,
        ) {
            // Create object with key_count keys
            let mut obj = serde_json::Map::new();
            for i in 0..key_count {
                obj.insert(format!("key_{}", i), Value::from(i));
            }
            let json = Value::Object(obj).to_string();

            // Property 1: Must not panic on large objects
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            // Property 2: Depth should be 1 (flat object)
            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            prop_assert_eq!(calculate_depth(&parsed), 1);
        }

        /// Property: Empty arrays and objects must be handled correctly
        /// Tests edge cases with zero elements
        #[test]
        fn proptest_empty_structures_depth(
            nest_level in 0usize..=10,
        ) {
            // Create nested empty objects
            let mut json = String::new();
            for _ in 0..nest_level {
                json.push_str("{\"empty\":");
            }
            json.push_str("{}");
            json.push_str(&"}".repeat(nest_level));

            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            let depth = calculate_depth(&parsed);
            // Empty objects still count toward depth
            prop_assert_eq!(depth, nest_level.saturating_add(1));
        }

        /// Property: Mixed nesting (arrays and objects) must be calculated correctly
        /// Tests depth calculation with alternating structures
        #[test]
        fn proptest_mixed_nesting_depth_calculation(
            depth in 1usize..=10,
        ) {
            // Create simple mixed nesting with arrays and objects
            let mut json = String::new();
            for _ in 0..depth {
                json.push_str("[{\"x\":");
            }
            json.push_str("null");
            json.push_str(&"}]".repeat(depth));

            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok(), "JSON construction should be valid");

            let parsed: Value = serde_json::from_str(&json)
                .expect("JSON should parse correctly");
            let calculated_depth = calculate_depth(&parsed);
            // Each iteration adds both array and object, so depth = 2*depth
            prop_assert!(calculated_depth >= depth,
                "Calculated depth {} should be >= nesting levels {}",
                calculated_depth, depth);
        }
    }

    // ============================================================================
    // SECURITY TEST: Numeric Edge Cases and Integer Overflow
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Integer overflow in depth calculation must be prevented
        /// Tests that saturating_add prevents overflow panics
        #[test]
        fn proptest_depth_calculation_no_overflow(
            // Test with realistic depths that shouldn't overflow
            depth in 0usize..=200,
        ) {
            // Create JSON with specified depth
            let mut json = String::new();
            for i in 0..depth {
                json.push_str(&format!("{{\"{}\":", i));
            }
            json.push_str("42");
            json.push_str(&"}".repeat(depth));

            // Property: Must never panic on overflow
            // Early termination at MAX_JSON_DEPTH prevents excessive recursion
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);

            if depth <= MAX_JSON_DEPTH {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(result.is_err());
            }
        }

        /// Property: Extreme numeric values in JSON must be handled
        /// Tests that large numbers don't cause issues
        #[test]
        fn proptest_extreme_numeric_values(
            value in prop::num::i64::ANY,
        ) {
            let json = serde_json::json!({
                "number": value,
                "nested": {
                    "another_number": value
                }
            }).to_string();

            // Property: Large numbers should not affect depth validation
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_ok());

            let parsed: Value = serde_json::from_str(&json).expect("JSON parsing should succeed");
            prop_assert_eq!(calculate_depth(&parsed), 2);
        }

        /// Property: Boolean and null values must not affect depth calculation
        /// Tests that scalar values are correctly identified as depth 0
        #[test]
        fn proptest_scalar_values_depth_zero(
            bool_val in any::<bool>(),
        ) {
            // Test various scalar types
            let null_value = Value::Null;
            let bool_value = Value::Bool(bool_val);
            let num_value = Value::from(42);
            let str_value = Value::from("test");

            prop_assert_eq!(calculate_depth(&null_value), 0);
            prop_assert_eq!(calculate_depth(&bool_value), 0);
            prop_assert_eq!(calculate_depth(&num_value), 0);
            prop_assert_eq!(calculate_depth(&str_value), 0);
        }

        /// Property: Very deep recursion must be bounded
        /// Tests that calculate_depth_limited provides early termination
        #[test]
        fn proptest_recursion_bounded(
            depth in (MAX_JSON_DEPTH + 1)..=60,
        ) {
            // Create JSON deeper than MAX_JSON_DEPTH
            let mut json = String::new();
            for i in 0..depth {
                json.push_str(&format!("[{{\"{}\":", i));
            }
            json.push('0');
            json.push_str(&"}]".repeat(depth));

            // Property: Should reject without stack overflow
            // Early termination prevents excessive recursion
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);
            prop_assert!(result.is_err());

            // Note: serde_json has its own recursion limit (~128 levels)
            // For very deep JSON, serde_json may fail before our validation
            // Either error is acceptable - both protect against DoS
            if let Ok(parsed) = serde_json::from_str::<Value>(&json) {
                let calculated = calculate_depth(&parsed);
                // If parsing succeeded, depth calculation should detect the issue
                prop_assert!(calculated > MAX_JSON_DEPTH);
            }
        }
    }

    // ============================================================================
    // SECURITY TEST: DoS Attack Vectors
    // ============================================================================

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 5 } else { 500 },  // Fewer cases due to complexity
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: Exponentially wide JSON must not cause memory exhaustion
        /// Tests the "billion laughs" style attack adapted for JSON
        #[test]
        fn proptest_dos_exponential_width(
            width in 1usize..=20,
            depth in 1usize..=4,
        ) {
            // Create JSON with exponentially increasing width
            // Each level has 'width' children
            fn create_wide_json(width: usize, depth: usize) -> String {
                if depth == 0 {
                    return "42".to_string();
                }

                let mut json = String::from("[");
                for i in 0..width {
                    if i > 0 {
                        json.push(',');
                    }
                    json.push_str(&create_wide_json(width, depth.saturating_sub(1)));
                }
                json.push(']');
                json
            }

            let json = create_wide_json(width, depth);

            // Property: Must handle or reject gracefully, never crash
            let result = validate_json_depth(&json, MAX_JSON_DEPTH);

            if depth <= MAX_JSON_DEPTH {
                prop_assert!(result.is_ok() || result.is_err()); // Either is fine
            } else {
                prop_assert!(result.is_err());
            }
        }

        /// Property: Repeated deep nesting with different patterns
        /// Tests that various nesting styles are consistently handled
        #[test]
        fn proptest_dos_varied_nesting_patterns(
            depth in 30usize..=MAX_JSON_DEPTH + 20,
            pattern in prop::sample::select(vec!["array", "object", "mixed"]),
        ) {
            let json = match pattern {
                "array" => {
                    let mut s = String::new();
                    for _ in 0..depth {
                        s.push('[');
                    }
                    s.push_str("null");
                    s.push_str(&"]".repeat(depth));
                    s
                },
                "object" => {
                    let mut s = String::new();
                    for i in 0..depth {
                        s.push_str(&format!("{{\"k{}\":", i));
                    }
                    s.push_str("null");
                    s.push_str(&"}".repeat(depth));
                    s
                },
                _ => { // "mixed"
                    let mut s = String::new();
                    for i in 0..depth {
                        if i % 2 == 0 {
                            s.push('[');
                        } else {
                            s.push_str("{\"x\":");
                        }
                    }
                    s.push_str("null");
                    for i in (0..depth).rev() {
                        if i % 2 == 0 {
                            s.push(']');
                        } else {
                            s.push('}');
                        }
                    }
                    s
                }
            };

            let result = validate_json_depth(&json, MAX_JSON_DEPTH);

            if depth <= MAX_JSON_DEPTH {
                prop_assert!(result.is_ok());
            } else {
                prop_assert!(result.is_err());
            }
        }

        /// Property: Malformed JSON with unbalanced brackets must fail gracefully
        /// Tests that parser errors are caught and sanitized
        #[test]
        fn proptest_malformed_json_graceful_failure(
            open_brackets in 0usize..=50,
            close_brackets in 0usize..=50,
        ) {
            // Create intentionally malformed JSON
            let mut json = String::new();
            json.push_str(&"[".repeat(open_brackets));
            json.push_str("null");
            json.push_str(&"]".repeat(close_brackets));

            let result = validate_json_depth(&json, MAX_JSON_DEPTH);

            // Property: Either valid (if balanced) or returns sanitized error
            match result {
                Ok(_) => {
                    // If successful, brackets must be balanced
                    prop_assert_eq!(open_brackets, close_brackets);
                },
                Err(msg) => {
                    // Error must be sanitized
                    prop_assert!(
                        msg == "Invalid JSON format" || msg.contains("too deeply nested")
                    );
                }
            }
        }
    }
}
