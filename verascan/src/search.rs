use crate::FileFinder;
use crate::cli::{Args, Commands};
use log::{debug, error, info};
use std::path::PathBuf;

/// Execute file search workflow
///
/// # Errors
/// Returns an error code if file search fails or no valid files are found
pub fn execute_file_search(args: &Args) -> Result<Vec<PathBuf>, i32> {
    let (filepath, filefilter, recursive, validate) = match &args.command {
        Commands::Pipeline {
            filepath,
            filefilter,
            recursive,
            validate,
            ..
        } => (filepath, filefilter, *recursive, *validate),
        Commands::Assessment {
            filepath,
            filefilter,
            recursive,
            validate,
            ..
        } => (filepath, filefilter, *recursive, *validate),
        Commands::Policy { .. } => {
            return Err(1); // Policy command doesn't need file search
        }
        Commands::Export { .. } => {
            return Err(1); // Export command doesn't need file search
        }
        Commands::HelpEnv => {
            return Err(1); // HelpEnv command doesn't need file search
        }
    };

    let finder = FileFinder::new();
    let config =
        FileFinder::parse_config(filepath, filefilter, recursive, validate).map_err(|e| {
            error!("Error: {e}");
            1
        })?;

    let matched_files = finder.search(&config).map_err(|e| {
        error!("Error: {e}");
        1
    })?;

    display_search_results(&matched_files, args, filefilter, recursive, validate)?;
    Ok(matched_files)
}

fn display_search_results(
    matched_files: &[PathBuf],
    args: &Args,
    filefilter: &str,
    recursive: bool,
    validate: bool,
) -> Result<(), i32> {
    let search_type = if recursive {
        "recursively"
    } else {
        "in directory"
    };

    if matched_files.is_empty() {
        match &args.command {
            Commands::Pipeline { .. } => {
                error!("❌ No files found for pipeline scan upload");
                error!(
                    "💡 Ensure files matching the pattern '{filefilter}' exist in the specified directory"
                );
                return Err(1);
            }
            Commands::Assessment { .. } => {
                error!("❌ No files found for assessment scan upload");
                error!(
                    "💡 Ensure files matching the pattern '{filefilter}' exist in the specified directory"
                );
                return Err(1);
            }
            Commands::Policy { .. } => {
                info!("No files found {search_type} matching the patterns: {filefilter}");
                return Ok(());
            }
            Commands::Export { .. } => {
                // Export command doesn't use file search, this shouldn't be reached
                return Ok(());
            }
            Commands::HelpEnv => {
                // HelpEnv command doesn't use file search, this shouldn't be reached
                return Ok(());
            }
        }
    }

    if validate {
        debug!("📊 Search completed with validation.");
        debug!("   Total valid files returned: {}", matched_files.len());
        debug!("   (Invalid files were filtered out and shown above)");
    } else {
        info!(
            "Found {} file(s) {} matching patterns '{}':",
            matched_files.len(),
            search_type,
            filefilter
        );
        for file in matched_files {
            info!("  {}", file.display());
        }
        info!(
            "\n💡 Use --validate (-v) to check file types by header signature and filter invalid files"
        );
    }

    Ok(())
}
