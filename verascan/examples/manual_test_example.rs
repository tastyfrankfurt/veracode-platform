#!/usr/bin/env rust-script

//! Manual Test Example for GitLab Issues Integration
//!
//! This example shows how to manually test the GitLab issues functionality
//! by creating a mock finding and sending it to GitLab.
//!
//! Usage:
//! 1. Set environment variables (PRIVATE_TOKEN, CI_PROJECT_ID)
//! 2. Run: cargo run --example manual_test_example

use std::collections::HashMap;
use std::env;
use veracode_platform::pipeline::{Finding, FindingFiles, FindingsSummary, ScanStatus, SourceFile};
use verascan::findings::{
    AggregatedFindings, AggregationStats, CweStatistic, FindingWithSource, ScanMetadata,
    ScanSource, create_finding_hash,
};
use verascan::gitlab_issues::GitLabIssuesClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 GitLab Issues Manual Test");
    println!("============================");

    // Check required environment variables
    check_environment_variables()?;

    // Create a mock finding for testing
    let mock_finding = create_mock_finding();
    let aggregated = create_mock_aggregated_findings(mock_finding);

    println!("📝 Created mock security finding:");
    println!("   Title: {}", aggregated.findings[0].finding.title);
    println!(
        "   Severity: {} ({})",
        aggregated.findings[0].finding.severity,
        get_severity_name(aggregated.findings[0].finding.severity)
    );
    println!(
        "   File: {}",
        aggregated.findings[0].finding.files.source_file.file
    );
    println!(
        "   Line: {}",
        aggregated.findings[0].finding.files.source_file.line
    );

    // Initialize GitLab client
    println!("\n🔗 Initializing GitLab client...");
    let mut client = GitLabIssuesClient::from_env(true)?;

    println!("✅ GitLab client initialized successfully");

    // Create issues from findings
    println!("\n📋 Creating GitLab issues...");
    match client.create_issues_from_findings(&aggregated).await {
        Ok(issues) => {
            println!("✅ Successfully created {} GitLab issue(s)!", issues.len());
            for issue in issues {
                println!("   📌 Issue #{}: {}", issue.iid, issue.title);
                println!("      URL: {}", issue.web_url);
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to create GitLab issues: {e}");
            return Err(e.into());
        }
    }

    println!("\n🎉 Test completed successfully!");
    println!("Check your GitLab project for the newly created security issue.");

    Ok(())
}

fn check_environment_variables() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Checking environment variables...");

    let token = env::var("PRIVATE_TOKEN")
        .or_else(|_| env::var("CI_TOKEN"))
        .or_else(|_| env::var("GITLAB_TOKEN"))
        .map_err(
            |_| "Missing required environment variable: PRIVATE_TOKEN, CI_TOKEN, or GITLAB_TOKEN",
        )?;

    let project_id = env::var("CI_PROJECT_ID")
        .map_err(|_| "Missing required environment variable: CI_PROJECT_ID")?;

    println!("✅ Environment variables found:");
    println!("   Token: {}...", &token[..std::cmp::min(8, token.len())]);
    println!("   Project ID: {project_id}");

    // Optional variables
    if let Ok(gitlab_url) = env::var("GITLAB_URL") {
        println!("   GitLab URL: {gitlab_url}");
    }
    if let Ok(pipeline_id) = env::var("CI_PIPELINE_ID") {
        println!("   Pipeline ID: {pipeline_id}");
    }

    Ok(())
}

fn create_mock_finding() -> FindingWithSource {
    let finding = Finding {
        issue_id: 12345,
        cwe_id: "79".to_string(),
        issue_type: "Cross-Site Scripting".to_string(),
        issue_type_id: "XSS".to_string(),
        severity: 4, // High severity
        title: "Cross-Site Scripting vulnerability in user input processing".to_string(),
        gob: "B".to_string(),
        display_text: "The application accepts user input without proper sanitization, leading to potential XSS attacks.".to_string(),
        flaw_details_link: Some("https://analysiscenter.veracode.com/auth/index.jsp#ViewReportsResultDetail:12345:79:XSS".to_string()),
        stack_dumps: None,
        files: FindingFiles {
            source_file: SourceFile {
                file: "src/main/webapp/userInput.jsp".to_string(),
                line: 42,
                function_name: Some("processUserInput".to_string()),
                qualified_function_name: "com.example.UserController.processUserInput".to_string(),
                function_prototype: "public String processUserInput(String input)".to_string(),
                scope: "public".to_string(),
            },
        },
    };

    let source_scan = ScanSource {
        scan_id: "test-scan-12345".to_string(),
        project_name: "Example Security Test Project".to_string(),
        source_file: "example-app.war".to_string(),
    };

    // Generate a proper finding_id using the actual hash function
    let hash = create_finding_hash(&finding);
    let finding_id = format!(
        "{}:{}:{}:{}",
        finding.cwe_id, finding.files.source_file.file, finding.files.source_file.line, hash
    );

    FindingWithSource {
        finding_id,
        finding,
        source_scan,
    }
}

fn create_mock_aggregated_findings(finding_with_source: FindingWithSource) -> AggregatedFindings {
    let scan_metadata = ScanMetadata {
        scan_id: "test-scan-12345".to_string(),
        project_name: "Example Security Test Project".to_string(),
        scan_status: ScanStatus::Success,
        project_uri: Some("https://gitlab.com/example/project".to_string()),
        source_file: "example-app.war".to_string(),
        finding_count: 1,
    };

    let summary = FindingsSummary {
        very_high: 0,
        high: 1, // Our test finding is high severity
        medium: 0,
        low: 0,
        very_low: 0,
        informational: 0,
        total: 1,
    };

    let stats = AggregationStats {
        total_scans: 1,
        total_findings: 1,
        unique_cwe_count: 1,
        unique_files_count: 1,
        top_cwe_ids: vec![CweStatistic {
            cwe_id: "79".to_string(),
            count: 1,
            percentage: 100.0,
        }],
        severity_distribution: HashMap::from([("High".to_string(), 1)]),
    };

    AggregatedFindings {
        scan_metadata: vec![scan_metadata],
        findings: vec![finding_with_source],
        summary,
        stats,
        original_rest_findings: None, // Example uses pipeline findings
    }
}

fn get_severity_name(severity: u32) -> &'static str {
    match severity {
        5 => "Very High",
        4 => "High",
        3 => "Medium",
        2 => "Low",
        1 => "Very Low",
        0 => "Info",
        _ => "Unknown",
    }
}
