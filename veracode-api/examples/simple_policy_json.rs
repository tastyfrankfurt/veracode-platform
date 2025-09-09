use veracode_platform::{FindingsQuery, GetBuildInfoRequest, VeracodeClient, VeracodeConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeracodeConfig::new(
        &std::env::var("VERACODE_API_ID").expect("VERACODE_API_ID required"),
        &std::env::var("VERACODE_API_KEY").expect("VERACODE_API_KEY required"),
    );

    // Accept either GUID or name for resolution
    let app_name_or_guid = std::env::var("APP_NAME")
        .or_else(|_| std::env::var("APP_GUID"))
        .expect("APP_NAME or APP_GUID environment variable required");
    // Policy will be extracted from the application profile

    let client = VeracodeClient::new(config.clone())?;
    let _policy_api = client.policy_api();
    let build_api = client.build_api();

    println!("🔍 Policy Scan Findings & Summary Report with GUID Resolution");

    // Resolve application GUID and extract policy
    let (app_guid, policy_guid) = if app_name_or_guid.contains('-') && app_name_or_guid.len() == 36
    {
        // Looks like a GUID, need to fetch the application to get policy
        println!("🔍 Fetching application details for GUID: {app_name_or_guid}");
        match client.get_application(&app_name_or_guid).await {
            Ok(app) => {
                let app_name = app
                    .profile
                    .as_ref()
                    .map(|p| &p.name)
                    .unwrap_or(&app_name_or_guid);
                println!("✅ Found application: {} (GUID: {})", app_name, app.guid);

                // Extract policy GUID from application profile
                let policy_guid = match &app.profile {
                    Some(profile) => match &profile.policies {
                        Some(policies) if !policies.is_empty() => {
                            let policy = &policies[0]; // Use first policy
                            println!("✅ Found policy: {} (GUID: {})", policy.name, policy.guid);
                            policy.guid.clone()
                        }
                        _ => {
                            println!("⚠️ No policy found for application");
                            String::from("no-policy-found")
                        }
                    },
                    None => {
                        println!("⚠️ No application profile found");
                        String::from("no-profile-found")
                    }
                };

                (app.guid.clone(), policy_guid)
            }
            Err(e) => {
                eprintln!("❌ Failed to fetch application by GUID: {e}");
                return Ok(());
            }
        }
    } else {
        // Looks like a name, resolve to GUID
        println!("🔍 Resolving application name to GUID: {app_name_or_guid}");
        match client.get_application_by_name(&app_name_or_guid).await {
            Ok(Some(app)) => {
                println!(
                    "✅ Found application: {} (GUID: {})",
                    app.profile
                        .as_ref()
                        .map(|p| &p.name)
                        .unwrap_or(&app_name_or_guid),
                    app.guid
                );

                // Extract policy GUID from application profile
                let policy_guid = match &app.profile {
                    Some(profile) => match &profile.policies {
                        Some(policies) if !policies.is_empty() => {
                            let policy = &policies[0]; // Use first policy
                            println!("✅ Found policy: {} (GUID: {})", policy.name, policy.guid);
                            policy.guid.clone()
                        }
                        _ => {
                            println!("⚠️ No policy found for application");
                            String::from("no-policy-found")
                        }
                    },
                    None => {
                        println!("⚠️ No application profile found");
                        String::from("no-profile-found")
                    }
                };

                (app.guid.clone(), policy_guid)
            }
            Ok(None) => {
                eprintln!("❌ Application not found: {app_name_or_guid}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("❌ Error searching for application: {e}");
                return Ok(());
            }
        }
    };

    println!("\n📊 Application: {app_guid} | Policy: {policy_guid}");

    // Convert app GUID to app ID for XML API calls
    let app_id = match client.get_app_id_from_guid(&app_guid).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("❌ Failed to get app ID from GUID: {e}");
            return Ok(());
        }
    };

    // Get latest build info for the policy scan
    println!("\n📡 Getting latest policy scan build information...");
    let build_info_request = GetBuildInfoRequest {
        app_id: app_id.clone(),
        build_id: None,   // Get latest build
        sandbox_id: None, // Policy scan (no sandbox)
    };

    match build_api.get_build_info(&build_info_request).await {
        Ok(build_info) => {
            println!("✅ Policy Scan Build Information:");

            // build_info is a Build struct with simpler fields
            println!("   Build ID: {}", build_info.build_id);
            println!("   App ID: {}", build_info.app_id);
            println!(
                "   Version: {}",
                build_info.version.as_deref().unwrap_or("N/A")
            );
            println!(
                "   App Name: {}",
                build_info.app_name.as_deref().unwrap_or("N/A")
            );
            println!(
                "   Platform: {}",
                build_info.platform.as_deref().unwrap_or("N/A")
            );
            println!(
                "   Policy Compliance: {}",
                build_info
                    .policy_compliance_status
                    .as_deref()
                    .unwrap_or("N/A")
            );
            println!(
                "   Rules Status: {}",
                build_info.rules_status.as_deref().unwrap_or("N/A")
            );

            // Test new structured Findings API for policy scans
            println!("\n🧪 Testing new structured Findings API for policy scan...");

            // Get first page of findings with pagination
            match client
                .findings_api()
                .get_findings(
                    &FindingsQuery::new(&app_guid) // No sandbox context = policy scan
                        .with_pagination(0, 10) // First page, 10 items
                        .with_severity(vec![3, 4, 5]),
                ) // High severity only
                .await
            {
                Ok(findings_response) => {
                    println!("✅ Structured Findings API Response:");
                    println!("   Total elements: {}", findings_response.total_elements());
                    println!(
                        "   Current page: {} of {}",
                        findings_response.current_page() + 1,
                        findings_response.total_pages()
                    );
                    println!(
                        "   Findings on this page: {}",
                        findings_response.findings().len()
                    );
                    println!("   Has next page: {}", findings_response.has_next_page());

                    // Display structured finding data
                    for (i, finding) in findings_response.findings().iter().enumerate() {
                        println!(
                            "\n   📋 Finding #{} (Issue ID: {})",
                            i + 1,
                            finding.issue_id
                        );
                        println!(
                            "      CWE-{}: {}",
                            finding.finding_details.cwe.id, finding.finding_details.cwe.name
                        );
                        println!(
                            "      Severity: {} | File: {} (line {})",
                            finding.finding_details.severity,
                            finding.finding_details.file_name,
                            finding.finding_details.file_line_number
                        );
                        println!(
                            "      Status: {} | Violates Policy: {}",
                            finding.finding_status.status, finding.violates_policy
                        );
                        if finding.violates_policy {
                            println!("      ⚠️  POLICY VIOLATION!");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Structured Findings API call failed: {e}");
                }
            }

            // Test auto-paginated collection (get all findings)
            println!("\n🔄 Testing auto-paginated findings collection...");
            match client
                .findings_api() // Use findings API
                .get_all_policy_findings(&app_guid)
                .await
            {
                Ok(all_findings) => {
                    println!(
                        "✅ Retrieved all {} findings across all pages",
                        all_findings.len()
                    );

                    // Show summary by severity
                    let mut severity_counts = std::collections::HashMap::new();
                    let mut policy_violations = 0;

                    for finding in &all_findings {
                        *severity_counts
                            .entry(finding.finding_details.severity)
                            .or_insert(0) += 1;
                        if finding.violates_policy {
                            policy_violations += 1;
                        }
                    }

                    println!("   📊 Findings by Severity:");
                    for severity in [5, 4, 3, 2, 1, 0] {
                        if let Some(count) = severity_counts.get(&severity) {
                            let severity_name = match severity {
                                5 => "Very High",
                                4 => "High",
                                3 => "Medium",
                                2 => "Low",
                                1 => "Very Low",
                                0 => "Informational",
                                _ => "Unknown",
                            };
                            println!(
                                "      Severity {severity} ({severity_name}): {count} findings"
                            );
                        }
                    }
                    println!("   ⚠️  Policy Violations: {policy_violations} findings");
                }
                Err(e) => {
                    eprintln!("❌ Auto-paginated findings collection failed: {e}");
                }
            }

            // Legacy raw API call for comparison
            println!("\n📡 Legacy raw API call for comparison...");
            let findings_endpoint =
                format!("/appsec/v2/applications/{app_guid}/findings?page=0&size=5");

            println!("📡 Calling findings endpoint for policy scan: {findings_endpoint}");

            match client.get(&findings_endpoint, None).await {
                Ok(response) => {
                    let status = response.status();
                    println!("✅ Legacy Findings Response Status: {status}");

                    let body = response.text().await?;
                    println!("\n📄 Legacy Raw JSON Response (truncated):");
                    // Truncate output for readability in comparison
                    let truncated = if body.len() > 1000 {
                        format!(
                            "{}...\n[Response truncated - {} total characters]",
                            &body[..1000],
                            body.len()
                        )
                    } else {
                        body
                    };
                    println!("{truncated}");
                }
                Err(e) => {
                    eprintln!("❌ Legacy Findings API call failed: {e}");
                }
            }

            // Get summary report for the policy scan (latest build)
            let summary_endpoint = format!("/appsec/v2/applications/{app_guid}/summary_report");

            println!("\n📡 Calling summary report endpoint for policy scan: {summary_endpoint}");

            match client.get(&summary_endpoint, None).await {
                Ok(response) => {
                    let status = response.status();
                    println!("✅ Summary Report Response Status: {status}");

                    let body = response.text().await?;
                    println!("\n📄 Policy Scan Summary Report JSON (truncated):");
                    let truncated = if body.len() > 1500 {
                        format!(
                            "{}...\n[Response truncated - {} total characters]",
                            &body[..1500],
                            body.len()
                        )
                    } else {
                        body
                    };
                    println!("{truncated}");
                }
                Err(e) => {
                    eprintln!("❌ Summary Report API call failed: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to get build info: {e}");
        }
    }

    println!("\n🎯 Policy Scan Findings API Testing Results:");
    println!(
        "This example demonstrated the new structured Findings API features for policy scans:"
    );
    println!("  1. Paginated findings retrieval with filtering (severity, etc.)");
    println!("  2. Auto-paginated collection to get all findings across pages");
    println!("  3. Rich structured data access (CWE details, file locations, severity)");
    println!("  4. Policy scan context (no sandbox context required)");
    println!("  5. Policy violation detection and analysis");
    println!("\n📋 Benefits:");
    println!("  • Type-safe access to finding details instead of raw JSON parsing");
    println!("  • Automatic pagination handling to collect all results");
    println!("  • Memory-efficient with Cow<> patterns for string handling");
    println!("  • Rich filtering capabilities (severity, CWE, scan type, etc.)");
    println!("\n📝 Usage:");
    println!("  export VERACODE_API_ID=\"your_api_id\"");
    println!("  export VERACODE_API_KEY=\"your_api_key\"");
    println!("  export APP_NAME=\"your_app_name\"        # or APP_GUID");
    println!("  cargo run --example simple_policy_json");

    Ok(())
}
