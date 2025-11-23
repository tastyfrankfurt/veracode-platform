use clap::Parser;
use log::{LevelFilter, debug, error};
use verascan::cli::print_environment_variables;
use verascan::credentials::load_veracode_credentials_from_env;
use verascan::{
    Args, Commands, create_veracode_config_from_credentials, create_veracode_config_with_proxy,
    execute_assessment_scan, execute_file_search, execute_findings_export, execute_pipeline_scan,
    execute_policy_download, load_credentials_and_proxy_from_vault,
};

fn main() {
    let args = Args::parse();

    // Handle help-env subcommand early (no credentials needed)
    if matches!(args.command, Commands::HelpEnv) {
        print_environment_variables();
        std::process::exit(0);
    }

    // Initialize logger based on debug flag
    // Set default log filters to reduce noise from upstream crates
    let mut builder = env_logger::Builder::from_default_env();

    // If RUST_LOG is not set, apply our default filters
    if std::env::var("RUST_LOG").is_err() {
        let log_filter = if args.debug {
            "verascan=debug,vaultrs=info,rustify=warn,tracing=warn"
        } else {
            "verascan=info,vaultrs=warn,rustify=warn,tracing=warn"
        };
        builder.parse_filters(log_filter);
    }

    builder
        .filter_level(if args.debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        })
        .init();

    // Validate conditional requirements early
    if let Err(e) = args.validate_conditional_requirements() {
        error!("❌ {e}");
        std::process::exit(1);
    }

    // Load credentials directly into VeracodeCredentials - no args exposure!
    let veracode_config = match std::env::var("VAULT_CLI_ADDR") {
        Ok(_) => {
            debug!("Vault configuration detected, attempting Vault credential and proxy loading");
            // Create runtime only for vault credential loading
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    error!("❌ Failed to create tokio runtime: {e}");
                    std::process::exit(1);
                }
            };
            match runtime.block_on(load_credentials_and_proxy_from_vault()) {
                Ok((credentials, proxy_url, proxy_username, proxy_password)) => {
                    // Create config with credentials and proxy - Vault proxy takes precedence!
                    match create_veracode_config_with_proxy(
                        credentials,
                        &args.region,
                        proxy_url,
                        proxy_username,
                        proxy_password,
                    ) {
                        Ok(config) => config,
                        Err(code) => {
                            error!("❌ Failed to create Veracode configuration");
                            std::process::exit(code);
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Failed to load credentials and proxy from vault: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(_) => {
            debug!("No vault configuration found, using environment credential loading");
            // Load credentials directly from environment - no args manipulation needed!
            match load_veracode_credentials_from_env() {
                Ok(credentials) => {
                    match create_veracode_config_from_credentials(credentials, &args.region) {
                        Ok(config) => config,
                        Err(code) => {
                            error!("❌ Failed to create Veracode configuration");
                            std::process::exit(code);
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Failed to load credentials from environment: {e}");
                    std::process::exit(1);
                }
            }
        }
    };

    match &args.command {
        Commands::Policy { policy_name } => {
            execute_policy_download(veracode_config, policy_name)
                .unwrap_or_else(|code| std::process::exit(code));
        }
        Commands::Pipeline { .. } => {
            // For file search operations, filepath is required
            let matched_files =
                execute_file_search(&args).unwrap_or_else(|code| std::process::exit(code));
            execute_pipeline_scan(&matched_files, &veracode_config, &args)
                .unwrap_or_else(|code| std::process::exit(code));
        }
        Commands::Assessment { .. } => {
            // For file search operations, filepath is required
            let matched_files =
                execute_file_search(&args).unwrap_or_else(|code| std::process::exit(code));
            execute_assessment_scan(&matched_files, &veracode_config, &args)
                .unwrap_or_else(|code| std::process::exit(code));
        }
        Commands::Export { .. } => {
            // Set up runtime for async execution
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    error!("❌ Failed to create tokio runtime: {e}");
                    std::process::exit(1);
                }
            };
            runtime.block_on(async {
                execute_findings_export(&veracode_config, &args)
                    .await
                    .unwrap_or_else(|code| std::process::exit(code));
            });
        }
        Commands::HelpEnv => {
            // Already handled above before credential loading
            unreachable!()
        }
    }
}
