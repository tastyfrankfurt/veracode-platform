use crate::FileFinder;
use crate::cli::{Args, Commands};
use std::path::PathBuf;

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
    };

    let finder = FileFinder::new();
    let config = FileFinder::parse_config(filepath, filefilter, recursive, validate, args.debug)
        .map_err(|e| {
            eprintln!("Error: {}", e);
            1
        })?;

    let matched_files = finder.search(&config).map_err(|e| {
        eprintln!("Error: {}", e);
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
                eprintln!("❌ No files found for pipeline scan upload");
                eprintln!(
                    "💡 Ensure files matching the pattern '{}' exist in the specified directory",
                    filefilter
                );
                return Err(1);
            }
            Commands::Assessment { .. } => {
                eprintln!("❌ No files found for assessment scan upload");
                eprintln!(
                    "💡 Ensure files matching the pattern '{}' exist in the specified directory",
                    filefilter
                );
                return Err(1);
            }
            Commands::Policy { .. } => {
                println!(
                    "No files found {} matching the patterns: {}",
                    search_type, filefilter
                );
                return Ok(());
            }
        }
    }

    if validate {
        if args.debug {
            println!("\n📊 Search completed with validation.");
            println!("   Total valid files returned: {}", matched_files.len());
            println!("   (Invalid files were filtered out and shown above)");
        }
    } else {
        println!(
            "Found {} file(s) {} matching patterns '{}':",
            matched_files.len(),
            search_type,
            filefilter
        );
        for file in matched_files {
            println!("  {}", file.display());
        }
        println!(
            "\n💡 Use --validate (-v) to check file types by header signature and filter invalid files"
        );
    }

    Ok(())
}
