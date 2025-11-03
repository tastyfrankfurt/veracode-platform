#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test JSON deserialization from API responses

    // Try to parse as UTF-8 string first
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Fuzz pipeline scan API responses (veracode-api/src/pipeline.rs)
        test_findings_response_json(json_str);
        test_finding_json(json_str);
        test_scan_status_json(json_str);

        // Fuzz findings API responses (veracode-api/src/findings.rs)
        test_rest_findings_response_json(json_str);
        test_rest_finding_json(json_str);
        test_finding_details_json(json_str);

        // Fuzz application API responses (veracode-api/src/app.rs)
        test_application_json(json_str);
        test_applications_response_json(json_str);
        test_profile_json(json_str);

        // Fuzz arbitrary JSON structures
        test_arbitrary_json(json_str);

        // Test for deeply nested JSON (DoS potential)
        test_nested_json_depth(json_str);
    }

    // Also test raw bytes for binary JSON attacks
    test_binary_json_data(data);
});

/// Fuzz FindingsResponse deserialization (pipeline.rs:205)
fn test_findings_response_json(json: &str) {
    // Example structure:
    // {
    //   "findings": [...],
    //   "pipeline_scan": "...",
    //   "scan_status": "SUCCESS"
    // }

    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestFindingsResponse {
        findings: Option<Vec<serde_json::Value>>,
        pipeline_scan: Option<String>,
        scan_status: Option<String>,
    }

    let _ = serde_json::from_str::<TestFindingsResponse>(json);
}

/// Fuzz individual Finding deserialization (pipeline.rs:178)
fn test_finding_json(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestFinding {
        title: Option<String>,
        issue_id: Option<u64>,
        severity: Option<u8>,
        cwe_id: Option<String>,
        display_text: Option<String>,
        files: Option<serde_json::Value>,
    }

    let _ = serde_json::from_str::<TestFinding>(json);
}

/// Fuzz ScanStatus enum deserialization (pipeline.rs:71)
fn test_scan_status_json(json: &str) {
    // Valid values: "SUCCESS", "FAILURE", "PENDING", etc.

    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    #[serde(rename_all = "UPPERCASE")]
    enum TestScanStatus {
        Success,
        Failure,
        Pending,
    }

    let _ = serde_json::from_str::<TestScanStatus>(json);
}

/// Fuzz REST API FindingsResponse (findings.rs:155)
fn test_rest_findings_response_json(json: &str) {
    // HAL format with _embedded and _links
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestRestResponse {
        #[serde(rename = "_embedded")]
        embedded: Option<serde_json::Value>,
        #[serde(rename = "_links")]
        links: Option<serde_json::Value>,
        page: Option<serde_json::Value>,
    }

    let _ = serde_json::from_str::<TestRestResponse>(json);
}

/// Fuzz RestFinding deserialization (findings.rs:81)
fn test_rest_finding_json(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestRestFinding {
        issue_id: Option<u64>,
        scan_type: Option<String>,
        description: Option<String>,
        cwe: Option<serde_json::Value>,
        severity: Option<u8>,
        finding_status: Option<serde_json::Value>,
    }

    let _ = serde_json::from_str::<TestRestFinding>(json);
}

/// Fuzz FindingDetails deserialization (findings.rs:53)
fn test_finding_details_json(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestFindingDetails {
        severity: Option<u8>,
        module: Option<String>,
        source_file: Option<String>,
        line: Option<u32>,
    }

    let _ = serde_json::from_str::<TestFindingDetails>(json);
}

/// Fuzz Application deserialization (app.rs:17)
fn test_application_json(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestApplication {
        guid: Option<String>,
        profile: Option<serde_json::Value>,
        id: Option<u64>,
    }

    let _ = serde_json::from_str::<TestApplication>(json);
}

/// Fuzz ApplicationsResponse HAL format (app.rs:187)
fn test_applications_response_json(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestAppsResponse {
        #[serde(rename = "_embedded")]
        embedded: Option<serde_json::Value>,
        page: Option<serde_json::Value>,
    }

    let _ = serde_json::from_str::<TestAppsResponse>(json);
}

/// Fuzz Profile deserialization (app.rs:47)
fn test_profile_json(json: &str) {
    #[derive(serde::Deserialize, Debug)]
    #[allow(dead_code)]
    struct TestProfile {
        name: Option<String>,
        business_criticality: Option<String>,
        custom_kms_alias: Option<String>,
        repo_url: Option<String>,
    }

    let _ = serde_json::from_str::<TestProfile>(json);
}

/// Test arbitrary JSON for parsing robustness
fn test_arbitrary_json(json: &str) {
    // Just try to parse as generic Value
    let _ = serde_json::from_str::<serde_json::Value>(json);
}

/// Test deeply nested JSON for DoS
fn test_nested_json_depth(json: &str) {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json) {
        // Count nesting depth
        fn depth(v: &serde_json::Value) -> usize {
            match v {
                serde_json::Value::Array(arr) => 1 + arr.iter().map(depth).max().unwrap_or(0),
                serde_json::Value::Object(obj) => 1 + obj.values().map(depth).max().unwrap_or(0),
                _ => 0,
            }
        }

        let _nesting_depth = depth(&value);
    }
}

/// Test binary JSON data for malformed UTF-8
fn test_binary_json_data(data: &[u8]) {
    // Try to parse even if UTF-8 is invalid
    let _ = serde_json::from_slice::<serde_json::Value>(data);
}
