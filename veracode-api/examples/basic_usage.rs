#![allow(clippy::expect_used)]

use veracode_platform::{VeracodeClient, VeracodeConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration with custom timeouts
    let config: VeracodeConfig = VeracodeConfig::new(
        &std::env::var("VERACODE_API_ID").expect("VERACODE_API_ID environment variable required"),
        &std::env::var("VERACODE_API_KEY").expect("VERACODE_API_KEY environment variable required"),
    )
    .with_connect_timeout(60) // 60 seconds connection timeout
    .with_request_timeout(600); // 10 minutes request timeout

    // Create client
    let client = VeracodeClient::new(config)?;

    // Get all applications
    let applications = client.get_applications(None).await?;
    println!(
        "Found {} applications",
        applications
            .embedded
            .as_ref()
            .map_or(0, |e| e.applications.len())
    );

    // Search for a specific application
    let search_results = client
        .search_applications_by_name("Test Application")
        .await?;
    println!(
        "Found {} applications matching 'Test Application'",
        search_results.len()
    );

    // Get non-compliant applications
    let non_compliant = client.get_non_compliant_applications().await?;
    println!("Found {} non-compliant applications", non_compliant.len());

    Ok(())
}
