use crate::cli::Args;
use crate::FileFinder;
use std::path::PathBuf;

pub fn execute_file_search(args: &Args) -> Result<Vec<PathBuf>, i32> {
    let filepath = args.filepath.as_ref().ok_or_else(|| {
        eprintln!("❌ Error: --filepath is required for file search operations");
        1
    })?;
    
    let finder = FileFinder::new();
    let config = FileFinder::parse_config(filepath, &args.filefilter, args.recursive, args.validate, args.debug)
        .map_err(|e| {
            eprintln!("Error: {}", e);
            1
        })?;
    
    let matched_files = finder.search(&config)
        .map_err(|e| {
            eprintln!("Error: {}", e);
            1
        })?;
    
    display_search_results(&matched_files, args)?;
    Ok(matched_files)
}

fn display_search_results(matched_files: &[PathBuf], args: &Args) -> Result<(), i32> {
    let search_type = if args.recursive { "recursively" } else { "in directory" };
    
    if matched_files.is_empty() {
        if args.pipeline_scan {
            eprintln!("❌ No files found for pipeline scan upload");
            eprintln!("💡 Ensure files matching the pattern '{}' exist in the specified directory", args.filefilter);
            return Err(1);
        } else {
            println!("No files found {} matching the patterns: {}", search_type, args.filefilter);
            return Ok(());
        }
    }

    if args.validate {
        if args.debug {
            println!("\n📊 Search completed with validation.");
            println!("   Total valid files returned: {}", matched_files.len());
            println!("   (Invalid files were filtered out and shown above)");
        }
    } else {
        println!("Found {} file(s) {} matching patterns '{}':", matched_files.len(), search_type, args.filefilter);
        for file in matched_files {
            println!("  {}", file.display());
        }
        println!("\n💡 Use --validate (-v) to check file types by header signature and filter invalid files");
    }
    
    Ok(())
}