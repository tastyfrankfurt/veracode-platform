#![allow(clippy::expect_used)]

use veracode_platform::{
    FindingsQuery, GetBuildInfoRequest, VeracodeClient, VeracodeConfig, validation::AppGuid,
};

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
    let sandbox_name_or_guid = std::env::var("SANDBOX_NAME")
        .or_else(|_| std::env::var("SANDBOX_GUID"))
        .expect("SANDBOX_NAME or SANDBOX_GUID environment variable required");
    // Policy will be extracted from the application profile

    let client = VeracodeClient::new(config.clone())?;
    let _policy_api = client.policy_api();
    let sandbox_api = client.sandbox_api();
    let build_api = client.build_api()?;

    println!(
        "🔍 Application Sandboxes, Raw XML, Findings & Summary Report with GUID Resolution & Latest Scan"
    );

    // Resolve application GUID and extract policy
    let (app_guid, policy_guid) = if app_name_or_guid.contains('-') && app_name_or_guid.len() == 36
    {
        // Looks like a GUID, need to fetch the application to get policy
        println!("🔍 Fetching application details for GUID: {app_name_or_guid}");
        match client
            .get_application(&AppGuid::new(&app_name_or_guid)?)
            .await
        {
            Ok(app) => {
                let app_name = app
                    .profile
                    .as_ref()
                    .map(|p| p.name.as_str())
                    .unwrap_or(&app_name_or_guid);
                println!("✅ Found application: {} (GUID: {})", app_name, app.guid);

                // Extract policy GUID from application profile
                let policy_guid = match &app.profile {
                    Some(profile) => match &profile.policies {
                        Some(policies) if !policies.is_empty() => {
                            let policy = policies.first().expect("should have first policy"); // Use first policy
                            println!("✅ Found policy: {} (GUID: {})", policy.name, policy.guid);
                            policy.guid.clone()
                        }
                        _ => {
                            eprintln!("❌ No policies found for application: {app_name}");
                            return Ok(());
                        }
                    },
                    None => {
                        eprintln!("❌ No profile found for application: {app_name_or_guid}");
                        return Ok(());
                    }
                };

                (app.guid, policy_guid)
            }
            Err(e) => {
                eprintln!("❌ Failed to fetch application details: {e}");
                return Ok(());
            }
        }
    } else {
        // Resolve by name
        println!("🔍 Resolving application GUID for: {app_name_or_guid}");
        match client.get_application_by_name(&app_name_or_guid).await {
            Ok(Some(app)) => {
                let app_name = app
                    .profile
                    .as_ref()
                    .map(|p| p.name.as_str())
                    .unwrap_or(&app_name_or_guid);
                println!("✅ Found application: {} (GUID: {})", app_name, app.guid);

                // Extract policy GUID from application profile
                let policy_guid = match &app.profile {
                    Some(profile) => match &profile.policies {
                        Some(policies) if !policies.is_empty() => {
                            let policy = policies.first().expect("should have first policy"); // Use first policy
                            println!("✅ Found policy: {} (GUID: {})", policy.name, policy.guid);
                            policy.guid.clone()
                        }
                        _ => {
                            eprintln!("❌ No policies found for application: {app_name}");
                            return Ok(());
                        }
                    },
                    None => {
                        eprintln!("❌ No profile found for application: {app_name_or_guid}");
                        return Ok(());
                    }
                };

                (app.guid, policy_guid)
            }
            Ok(None) => {
                eprintln!("❌ Application not found: {app_name_or_guid}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("❌ Failed to resolve application GUID: {e}");
                return Ok(());
            }
        }
    };

    // Resolve sandbox GUID
    let sandbox_guid = if sandbox_name_or_guid.contains('-') && sandbox_name_or_guid.len() == 36 {
        // Looks like a GUID
        sandbox_name_or_guid.clone()
    } else {
        // Resolve by name
        println!("🔍 Resolving sandbox GUID for: {sandbox_name_or_guid}");
        match sandbox_api
            .get_sandbox_by_name(&app_guid, &sandbox_name_or_guid)
            .await
        {
            Ok(Some(sandbox)) => {
                println!(
                    "✅ Found sandbox: {} (GUID: {})",
                    sandbox.name, sandbox.guid
                );
                sandbox.guid
            }
            Ok(None) => {
                eprintln!("❌ Sandbox not found: {sandbox_name_or_guid}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("❌ Failed to resolve sandbox GUID: {e}");
                return Ok(());
            }
        }
    };

    println!("\n📋 Resolved Information:");
    println!("App GUID: {app_guid}");
    println!("Sandbox GUID: {sandbox_guid}");
    println!("Policy GUID: {policy_guid} (from application profile)");

    // List all sandboxes for the application
    println!("\n📋 Listing all sandboxes for application:");
    let sandboxes_endpoint = format!("/appsec/v1/applications/{app_guid}/sandboxes");
    println!("📡 Calling sandboxes endpoint: {sandboxes_endpoint}");

    match client.get(&sandboxes_endpoint, None).await {
        Ok(response) => {
            let status = response.status();
            println!("✅ Sandboxes Response Status: {status}");

            let body = response.text().await?;
            println!("\n📄 Application Sandboxes JSON:");
            println!("{body}");
        }
        Err(e) => {
            eprintln!("❌ Sandboxes API call failed: {e}");
        }
    }

    // Get latest scan information
    println!("\n🔍 Getting latest scan information...");

    // Convert app GUID to app ID for XML API calls
    let app_id = match client.get_app_id_from_guid(&AppGuid::new(&app_guid)?).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("❌ Failed to get app ID from GUID: {e}");
            return Ok(());
        }
    };

    // Get sandbox ID from sandbox GUID
    match sandbox_api.list_sandboxes(&app_guid, None).await {
        Ok(sandboxes) => {
            if let Some(sandbox) = sandboxes.iter().find(|s| s.guid == sandbox_guid) {
                let sandbox_id = sandbox.id.unwrap_or(0).to_string();
                println!("✅ Found sandbox ID: {sandbox_id}");

                // Create XML client for raw API call
                let mut xml_config = config.clone();
                xml_config.base_url = xml_config.xml_base_url.clone();
                let xml_client = VeracodeClient::new(xml_config)?;

                // First, get raw XML from the build info API
                let xml_endpoint = "/api/5.0/getbuildinfo.do";
                let xml_query_params = [("app_id", app_id.as_str()), ("sandbox_id", &sandbox_id)];
                println!(
                    "\n📡 Calling XML build info endpoint: {xml_endpoint}?app_id={app_id}&sandbox_id={sandbox_id}"
                );

                match xml_client
                    .get_with_query_params(xml_endpoint, &xml_query_params)
                    .await
                {
                    Ok(response) => {
                        let status = response.status();
                        println!("✅ XML Build Info Response Status: {status}");

                        let xml_body = response.text().await?;
                        println!("\n📄 Raw XML Build Info Response:");
                        println!("{xml_body}");
                    }
                    Err(e) => {
                        eprintln!("❌ XML Build Info API call failed: {e}");
                    }
                }

                // Get latest build info for the sandbox
                let build_request = GetBuildInfoRequest {
                    app_id: app_id.to_string(),
                    build_id: None, // Get latest build
                    sandbox_id: Some(sandbox_id),
                };

                match build_api.get_build_info(&build_request).await {
                    Ok(build_info) => {
                        println!("\n✅ Latest scan found (parsed):");
                        println!("   Build ID: {}", build_info.build_id);
                        println!(
                            "   Version: {}",
                            build_info.version.as_deref().unwrap_or("N/A")
                        );
                        if let Some(policy_date) = &build_info.policy_updated_date {
                            println!(
                                "   Policy Updated: {}",
                                policy_date.format("%Y-%m-%d %H:%M:%S UTC")
                            );
                        }
                        println!(
                            "   Policy Compliance: {}",
                            build_info
                                .policy_compliance_status
                                .as_deref()
                                .unwrap_or("N/A")
                        );

                        // Test new structured Findings API
                        println!("\n🧪 Testing new structured Findings API...");

                        // Get first page of findings with pagination
                        match client
                            .findings_api()
                            .get_findings(
                                &FindingsQuery::for_sandbox(&app_guid, &sandbox_guid)
                                    .with_pagination(0, 10) // First page, 10 items
                                    .with_severity(vec![3, 4, 5]),
                            ) // High severity only
                            .await
                        {
                            Ok(findings_response) => {
                                println!("✅ Structured Findings API Response:");
                                println!(
                                    "   Total elements: {}",
                                    findings_response.total_elements()
                                );
                                println!(
                                    "   Current page: {} of {}",
                                    findings_response.current_page().saturating_add(1),
                                    findings_response.total_pages()
                                );
                                println!(
                                    "   Findings on this page: {}",
                                    findings_response.findings().len()
                                );
                                println!("   Has next page: {}", findings_response.has_next_page());

                                // Display structured finding data
                                for (i, finding) in findings_response.findings().iter().enumerate()
                                {
                                    let i: usize = i;
                                    println!(
                                        "\n   📋 Finding #{} (Issue ID: {})",
                                        i.saturating_add(1),
                                        finding.issue_id
                                    );
                                    println!(
                                        "      CWE-{}: {}",
                                        finding.finding_details.cwe.id,
                                        finding.finding_details.cwe.name
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
                            .get_all_sandbox_findings(&app_guid, &sandbox_guid)
                            .await
                        {
                            Ok(all_findings) => {
                                println!(
                                    "✅ Retrieved all {} findings across all pages",
                                    all_findings.len()
                                );

                                // Show summary by severity
                                let mut severity_counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
                                let mut policy_violations: usize = 0;

                                for finding in &all_findings {
                                    *severity_counts
                                        .entry(finding.finding_details.severity)
                                        .or_insert(0) = severity_counts
                                        .get(&finding.finding_details.severity)
                                        .unwrap_or(&0)
                                        .saturating_add(1);
                                    if finding.violates_policy {
                                        policy_violations = policy_violations.saturating_add(1);
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
                        let findings_endpoint = format!(
                            "/appsec/v2/applications/{app_guid}/findings?context={sandbox_guid}&page=0&size=5"
                        );

                        println!("📡 Calling findings endpoint for sandbox: {findings_endpoint}");

                        match client.get(&findings_endpoint, None).await {
                            Ok(response) => {
                                let status = response.status();
                                println!("✅ Legacy Findings Response Status: {status}");

                                let body = response.text().await?;
                                println!("\n📄 Legacy Raw JSON Response (truncated):");
                                // Truncate output for readability in comparison
                                //let truncated = if body.len() > 1000 {
                                //    format!(
                                //        "{}...\n[Response truncated - {} total characters]",
                                //        &body[..1000],
                                //        body.len()
                                //    )
                                //} else {
                                //    body
                                //};
                                println!("{body}");
                            }
                            Err(e) => {
                                eprintln!("❌ Legacy Findings API call failed: {e}");
                            }
                        }

                        // Get summary report for the sandbox (latest scan)
                        let summary_endpoint = format!(
                            "/appsec/v2/applications/{app_guid}/summary_report?context={sandbox_guid}"
                        );

                        println!(
                            "\n📡 Calling summary report endpoint for sandbox: {summary_endpoint}"
                        );

                        match client.get(&summary_endpoint, None).await {
                            Ok(response) => {
                                let status = response.status();
                                println!("✅ Summary Report Response Status: {status}");

                                let body = response.text().await?;
                                println!("\n📄 Latest Sandbox Summary Report JSON:");
                                println!("{body}");
                            }
                            Err(e) => {
                                eprintln!("❌ Summary Report API call failed: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to get latest build info: {e}");

                        // Fallback: still try to get sandbox data without build context

                        // Get findings
                        let findings_endpoint = format!(
                            "/appsec/v2/applications/{app_guid}/findings?context={sandbox_guid}"
                        );

                        println!("\n📡 Falling back to findings call: {findings_endpoint}");

                        match client.get(&findings_endpoint, None).await {
                            Ok(response) => {
                                let status = response.status();
                                println!("✅ Findings Response Status: {status}");

                                let body = response.text().await?;
                                println!("\n📄 Sandbox Findings JSON:");
                                println!("{body}");
                            }
                            Err(e) => {
                                eprintln!("❌ Findings API call failed: {e}");
                            }
                        }

                        // Get summary report
                        let summary_endpoint = format!(
                            "/appsec/v2/applications/{app_guid}/summary_report?context={sandbox_guid}"
                        );

                        println!("\n📡 Falling back to summary report call: {summary_endpoint}");

                        match client.get(&summary_endpoint, None).await {
                            Ok(response) => {
                                let status = response.status();
                                println!("✅ Summary Report Response Status: {status}");

                                let body = response.text().await?;
                                println!("\n📄 Sandbox Summary Report JSON:");
                                println!("{body}");
                            }
                            Err(e) => {
                                eprintln!("❌ Summary Report API call failed: {e}");
                            }
                        }
                    }
                }
            } else {
                eprintln!("❌ Could not find sandbox ID for GUID: {sandbox_guid}");
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to list sandboxes: {e}");
        }
    }

    println!("\n🎯 Findings API Testing Results:");
    println!("This example demonstrated the new structured Findings API features:");
    println!("  1. Paginated findings retrieval with filtering (severity, etc.)");
    println!("  2. Auto-paginated collection to get all findings across pages");
    println!("  3. Rich structured data access (CWE details, file locations, severity)");
    println!("  4. Sandbox context support for sandbox-specific findings");
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
    println!("  export SANDBOX_NAME=\"your_sandbox_name\" # or SANDBOX_GUID");
    println!("  cargo run --example simple_sandbox_policy_json");

    Ok(())
}
