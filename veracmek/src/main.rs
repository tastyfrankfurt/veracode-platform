//! # Veracmek - Customer Managed Encryption Key (CMEK) CLI Tool
//!
//! A command-line tool for managing Customer Managed Encryption Keys (CMEK) on Veracode application profiles.
//! This tool enables users to encrypt application data using their own AWS KMS keys.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use veracode_platform::{
    VeracodeClient, VeracodeError,
    app::{Application, ApplicationQuery, validate_kms_alias},
};

mod credentials;
mod vault_client;

use credentials::{create_veracode_config_from_credentials, create_veracode_config_with_proxy};
use vault_client::load_credentials_and_proxy_from_vault;

/// CLI for managing Customer Managed Encryption Keys (CMEK) on Veracode application profiles
#[derive(Parser)]
#[command(name = "veracmek")]
#[command(about = "A CLI tool for managing CMEK on Veracode application profiles")]
#[command(version)]
struct Cli {
    /// Set the log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Veracode API ID (can also be set via VERACODE_API_ID environment variable)
    #[arg(long)]
    api_id: Option<String>,

    /// Veracode API Key (can also be set via VERACODE_API_KEY environment variable)
    #[arg(long)]
    api_key: Option<String>,

    /// Veracode region (commercial, european, federal)
    #[arg(long = "region", default_value = "commercial", value_parser = validate_region)]
    region: String,

    /// Output format (json, table)
    #[arg(long, default_value = "table")]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug)]
enum OutputFormat {
    Json,
    Table,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "table" => Ok(OutputFormat::Table),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Table => write!(f, "table"),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Enable CMEK encryption on a single application
    Enable {
        /// Application GUID or name
        #[arg(short, long)]
        app: String,

        /// KMS alias to use for encryption (must start with 'alias/')
        #[arg(short, long)]
        kms_alias: String,
    },
    /// Change the encryption key for an application
    ChangeKey {
        /// Application GUID or name
        #[arg(short, long)]
        app: String,

        /// New KMS alias to use for encryption
        #[arg(short, long)]
        new_kms_alias: String,
    },
    /// Process all applications in the account
    Bulk {
        /// KMS alias to use for encryption
        #[arg(short, long)]
        kms_alias: String,

        /// Only show what would be done, don't make changes
        #[arg(long)]
        dry_run: bool,

        /// Skip applications that already have CMEK enabled
        #[arg(long)]
        skip_encrypted: bool,
    },
    /// Process applications from a JSON file
    FromFile {
        /// Path to JSON file containing application list
        #[arg(short, long)]
        file: PathBuf,

        /// Only show what would be done, don't make changes
        #[arg(long)]
        dry_run: bool,
    },
    /// Check encryption status of applications
    Status {
        /// Application GUID or name (optional - if not provided, shows all)
        #[arg(short, long)]
        app: Option<String>,
    },
    /// Display environment variables and JSON file format help
    HelpEnv,
}

/// Structure for JSON file input
#[derive(Debug, Serialize, Deserialize)]
struct AppEncryptionConfig {
    /// Application GUID or name
    pub app: String,
    /// KMS alias to use
    pub kms_alias: String,
    /// Optional: skip if already encrypted
    #[serde(default)]
    pub skip_if_encrypted: bool,
}

/// Structure for JSON file containing multiple applications
#[derive(Debug, Serialize, Deserialize)]
struct AppEncryptionList {
    pub applications: Vec<AppEncryptionConfig>,
}

/// Main application result type
type AppResult<T> = std::result::Result<T, AppError>;

/// Application error types
#[derive(thiserror::Error, Debug)]
enum AppError {
    #[error("Veracode API error: {0}")]
    Veracode(#[from] VeracodeError),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("File operation error: {0}")]
    File(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("General error: {0}")]
    General(#[from] anyhow::Error),

    #[error("Application not found: {0}")]
    AppNotFound(String),

    #[error("Invalid KMS alias: {0}")]
    InvalidKmsAlias(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle help-env subcommand early (no credentials needed)
    if matches!(cli.command, Commands::HelpEnv) {
        print_environment_variables();
        std::process::exit(0);
    }

    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(cli.log_level.parse().unwrap_or(log::LevelFilter::Info))
        .init();

    debug!("Starting veracmek with args: {:?}", std::env::args());

    // Create Veracode client
    let client = create_client(&cli)
        .await
        .context("Failed to create Veracode client")?;

    // Execute command
    match execute_command(&client, &cli.command, &cli.output).await {
        Ok(_) => {
            info!("Command completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Command failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Validate region string input
fn validate_region(region: &str) -> Result<String, String> {
    match region.to_lowercase().as_str() {
        "commercial" | "european" | "federal" => Ok(region.to_lowercase()),
        _ => Err(format!(
            "Invalid region '{}'. Valid options: commercial, european, federal",
            region
        )),
    }
}

/// Create a Veracode client from CLI configuration with Vault support
async fn create_client(cli: &Cli) -> AppResult<VeracodeClient> {
    // Create VeracodeConfig directly from credentials
    let veracode_config = match std::env::var("VAULT_CLI_ADDR") {
        Ok(_) => {
            debug!("Vault configuration detected, attempting Vault credential and proxy loading");
            match load_credentials_and_proxy_from_vault().await {
                Ok((credentials, proxy_url, proxy_username, proxy_password)) => {
                    // Create config with proxy credentials from Vault
                    match create_veracode_config_with_proxy(
                        credentials,
                        &cli.region,
                        proxy_url,
                        proxy_username,
                        proxy_password,
                    ) {
                        Ok(config) => config,
                        Err(_code) => {
                            return Err(AppError::Config(
                                "Failed to create Veracode configuration".to_string(),
                            ));
                        }
                    }
                }
                Err(e) => {
                    return Err(AppError::Config(format!(
                        "Failed to load credentials from vault: {e}"
                    )));
                }
            }
        }
        Err(_) => {
            debug!("No vault configuration found, using environment/CLI credential loading");
            // Load credentials directly from environment or CLI args
            match load_veracode_credentials_from_cli_or_env(cli) {
                Ok(credentials) => {
                    match create_veracode_config_from_credentials(credentials, &cli.region) {
                        Ok(config) => config,
                        Err(_code) => {
                            return Err(AppError::Config(
                                "Failed to create Veracode configuration".to_string(),
                            ));
                        }
                    }
                }
                Err(e) => {
                    return Err(AppError::Config(format!("Failed to load credentials: {e}")));
                }
            }
        }
    };

    VeracodeClient::new(veracode_config).map_err(AppError::from)
}

/// Load credentials from CLI arguments or environment variables
fn load_veracode_credentials_from_cli_or_env(
    cli: &Cli,
) -> Result<veracode_platform::VeracodeCredentials, String> {
    // Load credentials from CLI arguments or environment variables
    let api_id = cli
        .api_id
        .as_ref()
        .cloned()
        .or_else(|| std::env::var("VERACODE_API_ID").ok())
        .ok_or_else(|| {
            "API ID is required. Set --api-id or VERACODE_API_ID environment variable".to_string()
        })?;
    let api_key = cli
        .api_key
        .as_ref()
        .cloned()
        .or_else(|| std::env::var("VERACODE_API_KEY").ok())
        .ok_or_else(|| {
            "API Key is required. Set --api-key or VERACODE_API_KEY environment variable"
                .to_string()
        })?;

    Ok(veracode_platform::VeracodeCredentials::new(api_id, api_key))
}

/// Execute the selected command
async fn execute_command(
    client: &VeracodeClient,
    command: &Commands,
    output_format: &OutputFormat,
) -> AppResult<()> {
    match command {
        Commands::Enable { app, kms_alias } => {
            enable_encryption(client, app, kms_alias, output_format).await
        }
        Commands::ChangeKey { app, new_kms_alias } => {
            change_encryption_key(client, app, new_kms_alias, output_format).await
        }
        Commands::Bulk {
            kms_alias,
            dry_run,
            skip_encrypted,
        } => {
            bulk_enable_encryption(client, kms_alias, *dry_run, *skip_encrypted, output_format)
                .await
        }
        Commands::FromFile { file, dry_run } => {
            process_from_file(client, file, *dry_run, output_format).await
        }
        Commands::Status { app } => {
            show_encryption_status(client, app.as_ref(), output_format).await
        }
        Commands::HelpEnv => {
            // This should never be reached because help-env is handled early in main()
            unreachable!()
        }
    }
}

/// Enable encryption on a single application
async fn enable_encryption(
    client: &VeracodeClient,
    app_identifier: &str,
    kms_alias: &str,
    output_format: &OutputFormat,
) -> AppResult<()> {
    info!(
        "Enabling CMEK encryption on application: {}",
        app_identifier
    );

    // Validate KMS alias
    validate_kms_alias(kms_alias).map_err(AppError::InvalidKmsAlias)?;

    // Find application
    let app = find_application(client, app_identifier).await?;

    info!(
        "Found application: {} ({})",
        app.profile
            .as_ref()
            .map(|p| &p.name)
            .unwrap_or(&"Unknown".to_string()),
        app.guid
    );

    // Enable encryption
    let updated_app = client
        .enable_application_encryption(&app.guid, kms_alias)
        .await
        .map_err(AppError::from)?;

    // Output result
    match output_format {
        OutputFormat::Json => {
            let result = serde_json::json!({
                "success": true,
                "application": {
                    "guid": updated_app.guid,
                    "name": updated_app.profile.as_ref().map(|p| &p.name),
                    "kms_alias": kms_alias
                }
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table => {
            println!("✅ Successfully enabled CMEK encryption on application:");
            println!(
                "   Application: {} ({})",
                updated_app
                    .profile
                    .as_ref()
                    .map(|p| &p.name)
                    .unwrap_or(&"Unknown".to_string()),
                updated_app.guid
            );
            println!("   KMS Alias: {}", kms_alias);
        }
    }

    Ok(())
}

/// Change encryption key for an application
async fn change_encryption_key(
    client: &VeracodeClient,
    app_identifier: &str,
    new_kms_alias: &str,
    output_format: &OutputFormat,
) -> AppResult<()> {
    info!(
        "Changing encryption key for application: {}",
        app_identifier
    );

    // Validate KMS alias
    validate_kms_alias(new_kms_alias).map_err(AppError::InvalidKmsAlias)?;

    // Find application
    let app = find_application(client, app_identifier).await?;

    info!(
        "Found application: {} ({})",
        app.profile
            .as_ref()
            .map(|p| &p.name)
            .unwrap_or(&"Unknown".to_string()),
        app.guid
    );

    // Change encryption key
    let updated_app = client
        .change_encryption_key(&app.guid, new_kms_alias)
        .await
        .map_err(AppError::from)?;

    // Output result
    match output_format {
        OutputFormat::Json => {
            let result = serde_json::json!({
                "success": true,
                "application": {
                    "guid": updated_app.guid,
                    "name": updated_app.profile.as_ref().map(|p| &p.name),
                    "new_kms_alias": new_kms_alias
                }
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Table => {
            println!("✅ Successfully changed encryption key for application:");
            println!(
                "   Application: {} ({})",
                updated_app
                    .profile
                    .as_ref()
                    .map(|p| &p.name)
                    .unwrap_or(&"Unknown".to_string()),
                updated_app.guid
            );
            println!("   New KMS Alias: {}", new_kms_alias);
        }
    }

    Ok(())
}

/// Enable encryption on all applications in bulk
async fn bulk_enable_encryption(
    client: &VeracodeClient,
    kms_alias: &str,
    dry_run: bool,
    skip_encrypted: bool,
    output_format: &OutputFormat,
) -> AppResult<()> {
    info!(
        "Processing all applications for CMEK encryption (dry_run: {})",
        dry_run
    );

    // Validate KMS alias
    validate_kms_alias(kms_alias).map_err(AppError::InvalidKmsAlias)?;

    // Get all applications
    let query = ApplicationQuery::new();
    let apps_response = client
        .get_applications(Some(query))
        .await
        .map_err(AppError::from)?;

    let apps = apps_response
        .embedded
        .map(|e| e.applications)
        .unwrap_or_default();

    info!("Found {} applications to process", apps.len());

    let mut results = Vec::new();
    let mut processed = 0;
    let mut skipped = 0;
    let mut failed = 0;
    let apps_len = apps.len();

    for app in &apps {
        let app_name = app
            .profile
            .as_ref()
            .map(|p| p.name.as_str())
            .unwrap_or("Unknown");

        // Check if already encrypted and should skip
        if skip_encrypted
            && let Ok(Some(_)) = client.get_application_encryption_status(&app.guid).await
        {
            info!("Skipping {} - already encrypted", app_name);
            skipped += 1;
            continue;
        }

        if dry_run {
            info!(
                "Would enable CMEK encryption on: {} ({})",
                app_name, app.guid
            );
            results.push(serde_json::json!({
                "action": "would_enable",
                "application": {
                    "guid": app.guid,
                    "name": app_name,
                    "kms_alias": kms_alias
                }
            }));
        } else {
            match client
                .enable_application_encryption(&app.guid, kms_alias)
                .await
            {
                Ok(_) => {
                    info!("✅ Enabled CMEK encryption on: {} ({})", app_name, app.guid);
                    processed += 1;
                    results.push(serde_json::json!({
                        "action": "enabled",
                        "success": true,
                        "application": {
                            "guid": app.guid,
                            "name": app_name,
                            "kms_alias": kms_alias
                        }
                    }));
                }
                Err(e) => {
                    warn!(
                        "❌ Failed to enable CMEK encryption on: {} ({}): {}",
                        app_name, app.guid, e
                    );
                    failed += 1;
                    results.push(serde_json::json!({
                        "action": "enable",
                        "success": false,
                        "error": e.to_string(),
                        "application": {
                            "guid": app.guid,
                            "name": app_name,
                            "kms_alias": kms_alias
                        }
                    }));
                }
            }
        }
    }

    // Output results
    match output_format {
        OutputFormat::Json => {
            let summary = serde_json::json!({
                "dry_run": dry_run,
                "summary": {
                    "total": apps_len,
                    "processed": processed,
                    "skipped": skipped,
                    "failed": failed
                },
                "results": results
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        OutputFormat::Table => {
            if dry_run {
                println!("🔍 Dry run completed:");
            } else {
                println!("✅ Bulk operation completed:");
            }
            println!("   Total applications: {apps_len}");
            if !dry_run {
                println!("   Successfully processed: {processed}");
                println!("   Skipped: {skipped}");
                if failed > 0 {
                    println!("   Failed: {failed}");
                }
            }
        }
    }

    Ok(())
}

/// Process applications from a JSON file
async fn process_from_file(
    client: &VeracodeClient,
    file_path: &PathBuf,
    dry_run: bool,
    output_format: &OutputFormat,
) -> AppResult<()> {
    info!(
        "Processing applications from file: {:?} (dry_run: {})",
        file_path, dry_run
    );

    // Read and parse JSON file
    let file_content = std::fs::read_to_string(file_path).context("Failed to read input file")?;

    let app_list: AppEncryptionList =
        serde_json::from_str(&file_content).context("Failed to parse JSON file")?;

    info!("Found {} applications in file", app_list.applications.len());

    let mut results = Vec::new();
    let mut processed = 0;
    let mut skipped = 0;
    let mut failed = 0;
    let total_apps = app_list.applications.len();

    for app_config in &app_list.applications {
        // Validate KMS alias
        if let Err(e) = validate_kms_alias(&app_config.kms_alias) {
            warn!("❌ Invalid KMS alias for {}: {}", app_config.app, e);
            failed += 1;
            continue;
        }

        // Find application
        let app = match find_application(client, &app_config.app).await {
            Ok(app) => app,
            Err(e) => {
                warn!("❌ Failed to find application {}: {}", app_config.app, e);
                failed += 1;
                continue;
            }
        };

        let app_name = app
            .profile
            .as_ref()
            .map(|p| p.name.as_str())
            .unwrap_or("Unknown");

        // Check if already encrypted and should skip
        if app_config.skip_if_encrypted
            && let Ok(Some(_)) = client.get_application_encryption_status(&app.guid).await
        {
            info!("Skipping {} - already encrypted", app_name);
            skipped += 1;
            continue;
        }

        if dry_run {
            info!(
                "Would enable CMEK encryption on: {} ({})",
                app_name, app.guid
            );
            results.push(serde_json::json!({
                "action": "would_enable",
                "application": {
                    "guid": app.guid,
                    "name": app_name,
                    "kms_alias": app_config.kms_alias
                }
            }));
        } else {
            match client
                .enable_application_encryption(&app.guid, &app_config.kms_alias)
                .await
            {
                Ok(_) => {
                    info!("✅ Enabled CMEK encryption on: {} ({})", app_name, app.guid);
                    processed += 1;
                    results.push(serde_json::json!({
                        "action": "enabled",
                        "success": true,
                        "application": {
                            "guid": app.guid,
                            "name": app_name,
                            "kms_alias": app_config.kms_alias
                        }
                    }));
                }
                Err(e) => {
                    warn!(
                        "❌ Failed to enable CMEK encryption on: {} ({}): {}",
                        app_name, app.guid, e
                    );
                    failed += 1;
                    results.push(serde_json::json!({
                        "action": "enable",
                        "success": false,
                        "error": e.to_string(),
                        "application": {
                            "guid": app.guid,
                            "name": app_name,
                            "kms_alias": app_config.kms_alias
                        }
                    }));
                }
            }
        }
    }

    // Output results
    match output_format {
        OutputFormat::Json => {
            let summary = serde_json::json!({
                "dry_run": dry_run,
                "summary": {
                    "total": total_apps,
                    "processed": processed,
                    "skipped": skipped,
                    "failed": failed
                },
                "results": results
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        OutputFormat::Table => {
            if dry_run {
                println!("🔍 Dry run completed:");
            } else {
                println!("✅ File processing completed:");
            }
            println!("   Total applications in file: {total_apps}");
            if !dry_run {
                println!("   Successfully processed: {processed}");
                println!("   Skipped: {skipped}");
                if failed > 0 {
                    println!("   Failed: {failed}");
                }
            }
        }
    }

    Ok(())
}

/// Show encryption status of applications
async fn show_encryption_status(
    client: &VeracodeClient,
    app_identifier: Option<&String>,
    output_format: &OutputFormat,
) -> AppResult<()> {
    match app_identifier {
        Some(identifier) => {
            // Show status for specific application
            let app = find_application(client, identifier).await?;
            let status = client
                .get_application_encryption_status(&app.guid)
                .await
                .map_err(AppError::from)?;

            match output_format {
                OutputFormat::Json => {
                    let result = serde_json::json!({
                        "application": {
                            "guid": app.guid,
                            "name": app.profile.as_ref().map(|p| &p.name),
                            "encrypted": status.is_some(),
                            "kms_alias": status
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                OutputFormat::Table => {
                    println!(
                        "Application: {} ({})",
                        app.profile
                            .as_ref()
                            .map(|p| &p.name)
                            .unwrap_or(&"Unknown".to_string()),
                        app.guid
                    );
                    match status {
                        Some(kms_alias) => {
                            println!("🔒 CMEK Encryption: ENABLED");
                            println!("   KMS Alias: {}", kms_alias);
                        }
                        None => {
                            println!("🔓 CMEK Encryption: DISABLED");
                        }
                    }
                }
            }
        }
        None => {
            // Show status for all applications
            info!("Retrieving encryption status for all applications");

            let query = ApplicationQuery::new();
            let apps_response = client
                .get_applications(Some(query))
                .await
                .map_err(AppError::from)?;

            let apps = apps_response
                .embedded
                .map(|e| e.applications)
                .unwrap_or_default();

            let mut results = Vec::new();
            let mut encrypted_count = 0;
            let mut unencrypted_count = 0;

            for app in apps {
                let app_name = app
                    .profile
                    .as_ref()
                    .map(|p| p.name.as_str())
                    .unwrap_or("Unknown");

                match client.get_application_encryption_status(&app.guid).await {
                    Ok(status) => {
                        let encrypted = status.is_some();
                        if encrypted {
                            encrypted_count += 1;
                        } else {
                            unencrypted_count += 1;
                        }

                        results.push(serde_json::json!({
                            "guid": app.guid,
                            "name": app_name,
                            "encrypted": encrypted,
                            "kms_alias": status
                        }));
                    }
                    Err(e) => {
                        warn!("Failed to get encryption status for {}: {}", app_name, e);
                        results.push(serde_json::json!({
                            "guid": app.guid,
                            "name": app_name,
                            "encrypted": null,
                            "error": e.to_string()
                        }));
                    }
                }
            }

            // Output results
            match output_format {
                OutputFormat::Json => {
                    let summary = serde_json::json!({
                        "summary": {
                            "total": results.len(),
                            "encrypted": encrypted_count,
                            "unencrypted": unencrypted_count
                        },
                        "applications": results
                    });
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
                OutputFormat::Table => {
                    println!("📊 Encryption Status Summary:");
                    println!("   Total applications: {}", results.len());
                    println!("   🔒 Encrypted: {}", encrypted_count);
                    println!("   🔓 Unencrypted: {}", unencrypted_count);
                    println!();

                    for result in &results {
                        let name = result["name"].as_str().unwrap_or("Unknown");
                        let guid = result["guid"].as_str().unwrap_or("Unknown");
                        let encrypted = result["encrypted"].as_bool();

                        match encrypted {
                            Some(true) => {
                                let alias = result["kms_alias"].as_str().unwrap_or("Unknown");
                                println!("🔒 {} ({}) - {}", name, guid, alias);
                            }
                            Some(false) => {
                                println!("🔓 {} ({}) - Not encrypted", name, guid);
                            }
                            None => {
                                println!("❓ {} ({}) - Status unknown", name, guid);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Find an application by GUID or name
async fn find_application(client: &VeracodeClient, identifier: &str) -> AppResult<Application> {
    // First try to get by GUID (if it looks like a GUID)
    if identifier.len() == 36 && identifier.contains('-') {
        match client.get_application(identifier).await {
            Ok(app) => return Ok(app),
            Err(_) => {
                // Not found by GUID, try by name
            }
        }
    }

    // Search by name
    let query = ApplicationQuery::new().with_name(identifier);
    let apps_response = client
        .get_applications(Some(query))
        .await
        .map_err(AppError::from)?;

    let apps = apps_response
        .embedded
        .map(|e| e.applications)
        .unwrap_or_default();

    match apps.len() {
        0 => Err(AppError::AppNotFound(identifier.to_string())),
        1 => Ok(apps.into_iter().next().unwrap()),
        _ => {
            // Multiple matches - look for exact name match
            for app in apps {
                if let Some(profile) = &app.profile
                    && profile.name == identifier
                {
                    return Ok(app);
                }
            }
            Err(AppError::AppNotFound(format!(
                "Multiple applications found with name containing '{}', please use GUID instead",
                identifier
            )))
        }
    }
}

/// Print available environment variables and JSON file format information
fn print_environment_variables() {
    println!("🔧 Veracmek Environment Variables\n");

    println!("📡 Authentication & Configuration:");
    println!("   VERACODE_API_ID          - Your Veracode API ID (alphanumeric only)");
    println!("   VERACODE_API_KEY         - Your Veracode API Key (alphanumeric only)");
    println!("   RUST_LOG                 - Set logging level (error,warn,info,debug,trace)");
    println!();

    println!("🔐 Vault Configuration (Optional - for secure credential management):");
    println!("   VAULT_CLI_ADDR           - Vault server address (must use HTTPS)");
    println!("   VAULT_CLI_JWT            - JWT token for Vault authentication");
    println!("   VAULT_CLI_ROLE           - Vault role name for authentication");
    println!(
        "   VAULT_CLI_SECRET_PATH    - Path to secret in Vault (e.g., 'secret/veracode@kvv2')"
    );
    println!("   VAULT_CLI_NAMESPACE      - Vault namespace (optional)");
    println!("   VAULT_CLI_AUTH_PATH      - Vault auth path (optional, defaults to 'auth/jwt')");
    println!();

    println!("🌐 HTTP/HTTPS Proxy Configuration:");
    println!("   HTTPS_PROXY              - HTTPS proxy URL (e.g., 'http://proxy:8080')");
    println!("   HTTP_PROXY               - HTTP proxy URL (HTTPS_PROXY takes precedence)");
    println!("   PROXY_USERNAME           - Proxy username for authentication (optional)");
    println!("   PROXY_PASSWORD           - Proxy password for authentication (optional)");
    println!();
    println!("   Note: Proxy configuration from Vault takes precedence over environment variables");
    println!();

    println!("🔒 Security Configuration (Development Only):");
    println!("   VERACMEK_DISABLE_CERT_VALIDATION - Set to 'true' to disable TLS cert validation");
    println!(
        "                                      (affects both Veracode API and Vault connections)"
    );
    println!();

    println!("📄 JSON File Format for 'from-file' Command:\n");

    let example_config = serde_json::json!({
        "applications": [
            {
                "app": "my-app-guid-or-name",
                "kms_alias": "alias/my-cmek-key",
                "skip_if_encrypted": false
            },
            {
                "app": "another-application",
                "kms_alias": "alias/another-cmek-key",
                "skip_if_encrypted": true
            }
        ]
    });

    println!("{}", serde_json::to_string_pretty(&example_config).unwrap());
    println!();

    println!("📋 JSON File Field Descriptions:");
    println!("   applications         - Array of application configurations");
    println!("   app                  - Application GUID or name to process");
    println!("   kms_alias           - AWS KMS alias to use (must start with 'alias/')");
    println!(
        "   skip_if_encrypted   - Skip app if it already has CMEK enabled (optional, default: false)"
    );
    println!();

    println!("💡 Examples:");
    println!();
    println!("Basic usage:");
    println!("   veracmek from-file --file apps.json");
    println!("   veracmek from-file --file apps.json --dry-run");
    println!("   veracmek enable --app my-app --kms-alias alias/my-key");
    println!("   veracmek bulk --kms-alias alias/my-key --dry-run --skip-encrypted");
    println!();
    println!("Proxy configuration:");
    println!("   export HTTPS_PROXY=\"http://proxy.example.com:8080\"");
    println!("   export PROXY_USERNAME=\"myuser\"");
    println!("   export PROXY_PASSWORD=\"mypassword\"");
    println!();
    println!("Vault with proxy (in Vault secret JSON):");
    println!("   {{");
    println!("     \"api_id\": \"your-veracode-api-id\",");
    println!("     \"api_secret\": \"your-veracode-api-secret\",");
    println!("     \"proxy_url\": \"http://proxy.example.com:8080\",");
    println!("     \"proxy_username\": \"myuser\",");
    println!("     \"proxy_password\": \"mypassword\"");
    println!("   }}");
}
