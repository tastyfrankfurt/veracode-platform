use clap::Parser;
use verascan::{
    Args, Commands, execute_assessment_scan, execute_file_search, execute_pipeline_scan,
    execute_policy_download, load_api_credentials,
};

fn main() {
    let mut args = Args::parse();

    if load_api_credentials(&mut args).is_err() {
        std::process::exit(1);
    }

    // Validate conditional requirements
    if let Err(e) = args.validate_conditional_requirements() {
        eprintln!("❌ {}", e);
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
    }
}
