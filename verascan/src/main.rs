use clap::Parser;
use verascan::{Args, load_api_credentials, execute_file_search, execute_pipeline_scan, execute_policy_download};

fn main() {
    let mut args = Args::parse();
    
    if load_api_credentials(&mut args).is_err() {
        std::process::exit(1);
    }
    
    // Handle policy download command
    if args.request_policy.is_some() {
        execute_policy_download(&args).unwrap_or_else(|code| std::process::exit(code));
        return;
    }
    
    
    // For file search operations, filepath is required
    let matched_files = execute_file_search(&args).unwrap_or_else(|code| std::process::exit(code));
    
    if args.pipeline_scan {
        execute_pipeline_scan(&matched_files, &args).unwrap_or_else(|code| std::process::exit(code));
    }
}