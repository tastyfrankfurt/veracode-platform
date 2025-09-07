use clap::Parser;
use log::{LevelFilter, debug, error, info, warn};
use verascan::{
    Args, Commands, execute_assessment_scan, execute_file_search, execute_findings_export,
    execute_pipeline_scan, execute_policy_download, load_api_credentials,
    load_secure_api_credentials_with_vault,
};

fn main() {
    let args = Args::parse();

    // Initialize logger based on debug flag
    env_logger::Builder::from_default_env()
        .filter_level(if args.debug {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        })
        .init();

    let mut args = args;

    // Try enhanced credential loading with vault support first
    match std::env::var("VAULT_CLI_ADDR") {
        Ok(_) => {
            debug!("Vault configuration detected, attempting enhanced credential loading");
            // Create runtime only for vault credential loading
            let runtime = tokio::runtime::Runtime::new().unwrap();
            match runtime.block_on(load_secure_api_credentials_with_vault()) {
                Ok(secure_creds) => {
                    info!("Successfully loaded credentials via enhanced method");
                    // Convert secure credentials back to args format for compatibility
                    if let Ok((api_id, api_key)) = secure_creds.extract_credentials() {
                        args.api_id = Some(api_id);
                        args.api_key = Some(api_key);
                    } else {
                        error!("❌ Failed to extract credentials from secure wrapper");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    warn!("Enhanced credential loading failed: {e}");
                    error!("❌ Failed to load credentials: {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(_) => {
            debug!("No vault configuration found, using legacy credential loading");
            if load_api_credentials(&mut args).is_err() {
                std::process::exit(1);
            }
        }
    }

    // Validate conditional requirements
    if let Err(e) = args.validate_conditional_requirements() {
        error!("❌ {e}");
        std::process::exit(1);
    }

    match &args.command {
        Commands::Policy { policy_name } => {
            execute_policy_download(&args, policy_name)
                .unwrap_or_else(|code| std::process::exit(code));
        }
        Commands::Pipeline { .. } => {
            // For file search operations, filepath is required
            let matched_files =
                execute_file_search(&args).unwrap_or_else(|code| std::process::exit(code));
            execute_pipeline_scan(&matched_files, &args)
                .unwrap_or_else(|code| std::process::exit(code));
        }
        Commands::Assessment { .. } => {
            // For file search operations, filepath is required
            let matched_files =
                execute_file_search(&args).unwrap_or_else(|code| std::process::exit(code));
            execute_assessment_scan(&matched_files, &args)
                .unwrap_or_else(|code| std::process::exit(code));
        }
        Commands::Export { .. } => {
            // Set up runtime for async execution
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                execute_findings_export(&args)
                    .await
                    .unwrap_or_else(|code| std::process::exit(code));
            });
        }
    }
}
