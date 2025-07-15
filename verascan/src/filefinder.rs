use crate::filevalidator::{FileValidator, ValidationError};
use glob::Pattern;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub directory: PathBuf,
    pub patterns: Vec<Pattern>,
    pub recursive: bool,
    pub validate_files: bool,
    pub debug: bool,
}

#[derive(Debug)]
pub enum SearchError {
    InvalidPattern(String),
    DirectoryNotFound(String),
    NotADirectory(String),
    IoError(String),
}

impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchError::InvalidPattern(msg) => write!(f, "Invalid pattern: {}", msg),
            SearchError::DirectoryNotFound(msg) => write!(f, "Directory not found: {}", msg),
            SearchError::NotADirectory(msg) => write!(f, "Not a directory: {}", msg),
            SearchError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for SearchError {}

pub struct FileFinder {
    validator: FileValidator,
}

impl FileFinder {
    pub fn new() -> Self {
        FileFinder {
            validator: FileValidator::new(),
        }
    }

    pub fn parse_config(
        directory: &str,
        patterns_str: &str,
        recursive: bool,
        validate_files: bool,
        debug: bool,
    ) -> Result<SearchConfig, SearchError> {
        // Validate directory
        let dir_path = Path::new(directory);
        if !dir_path.exists() {
            return Err(SearchError::DirectoryNotFound(directory.to_string()));
        }

        if !dir_path.is_dir() {
            return Err(SearchError::NotADirectory(directory.to_string()));
        }

        // Parse comma-separated patterns
        let patterns: Result<Vec<Pattern>, _> = patterns_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|pattern| {
                Pattern::new(pattern)
                    .map_err(|e| SearchError::InvalidPattern(format!("'{}': {}", pattern, e)))
            })
            .collect();

        let patterns = patterns?;

        if patterns.is_empty() {
            return Err(SearchError::InvalidPattern(
                "No valid patterns provided".to_string(),
            ));
        }

        Ok(SearchConfig {
            directory: dir_path.to_path_buf(),
            patterns,
            recursive,
            validate_files,
            debug,
        })
    }

    pub fn search(&self, config: &SearchConfig) -> Result<Vec<PathBuf>, SearchError> {
        let mut matched_files = Vec::new();

        if config.recursive {
            self.search_recursive(
                &config.directory,
                &config.patterns,
                &mut matched_files,
                config,
            )?;
        } else {
            self.search_directory(
                &config.directory,
                &config.patterns,
                &mut matched_files,
                config,
            )?;
        }

        // Sort the results for consistent output
        matched_files.sort();
        Ok(matched_files)
    }

    fn search_directory(
        &self,
        dir_path: &Path,
        patterns: &[Pattern],
        matched_files: &mut Vec<PathBuf>,
        config: &SearchConfig,
    ) -> Result<(), SearchError> {
        let entries = fs::read_dir(dir_path).map_err(|e| {
            SearchError::IoError(format!(
                "Failed to read directory '{}': {}",
                dir_path.display(),
                e
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SearchError::IoError(format!("Error reading directory entry: {}", e))
            })?;

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    eprintln!(
                        "Warning: Could not determine file type for {}: {}",
                        entry.path().display(),
                        e
                    );
                    continue;
                }
            };

            if file_type.is_file() {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                // Check if the filename matches any of the patterns
                for pattern in patterns {
                    if pattern.matches(&file_name_str) {
                        let file_path = entry.path();

                        // Validate file if validation is enabled
                        if config.validate_files {
                            match self.validator.validate_file(&file_path, config.debug) {
                                Ok(file_type) => {
                                    let suitable =
                                        self.validator.is_suitable_for_static_analysis(&file_type);
                                    if config.debug {
                                        println!("✅ Valid file: {}", file_path.display());
                                        println!(
                                            "   Type: {} ({})",
                                            file_type,
                                            self.validator.get_file_type_description(&file_type)
                                        );
                                        println!(
                                            "   Static Analysis: {}",
                                            if suitable {
                                                "✅ Suitable"
                                            } else {
                                                "❌ Not recommended"
                                            }
                                        );
                                    } else {
                                        println!("✅ Valid file: {}", file_path.display());
                                    }
                                    matched_files.push(file_path);
                                }
                                Err(ValidationError::UnsupportedFileType(msg)) => {
                                    if config.debug {
                                        println!(
                                            "⚠️  Unsupported file type: {}",
                                            file_path.display()
                                        );
                                        println!("   Reason: {}", msg);
                                    }
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::InvalidFileHeader(msg)) => {
                                    if config.debug {
                                        println!("❌ Invalid file: {}", file_path.display());
                                        println!("   Reason: {}", msg);
                                    }
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::IoError(msg)) => {
                                    if config.debug {
                                        println!(
                                            "❌ IO Error reading file: {}",
                                            file_path.display()
                                        );
                                        println!("   Reason: {}", msg);
                                    }
                                    // Don't add to matched_files - filter it out
                                }
                            }
                        } else {
                            // No validation - just add the file
                            matched_files.push(file_path);
                        }
                        break; // Don't check other patterns for the same file
                    }
                }
            }
        }
        Ok(())
    }

    fn search_recursive(
        &self,
        dir_path: &Path,
        patterns: &[Pattern],
        matched_files: &mut Vec<PathBuf>,
        config: &SearchConfig,
    ) -> Result<(), SearchError> {
        let entries = match fs::read_dir(dir_path) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!(
                    "Warning: Failed to read directory '{}': {}",
                    dir_path.display(),
                    e
                );
                return Ok(()); // Continue with other directories
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!("Warning: Error reading directory entry: {}", e);
                    continue;
                }
            };

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    eprintln!(
                        "Warning: Could not determine file type for {}: {}",
                        entry.path().display(),
                        e
                    );
                    continue;
                }
            };

            if file_type.is_file() {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                // Check if the filename matches any of the patterns
                for pattern in patterns {
                    if pattern.matches(&file_name_str) {
                        let file_path = entry.path();

                        // Validate file if validation is enabled
                        if config.validate_files {
                            match self.validator.validate_file(&file_path, config.debug) {
                                Ok(file_type) => {
                                    let suitable =
                                        self.validator.is_suitable_for_static_analysis(&file_type);
                                    if config.debug {
                                        println!("✅ Valid file: {}", file_path.display());
                                        println!(
                                            "   Type: {} ({})",
                                            file_type,
                                            self.validator.get_file_type_description(&file_type)
                                        );
                                        println!(
                                            "   Static Analysis: {}",
                                            if suitable {
                                                "✅ Suitable"
                                            } else {
                                                "❌ Not recommended"
                                            }
                                        );
                                    } else {
                                        println!("✅ Valid file: {}", file_path.display());
                                    }
                                    matched_files.push(file_path);
                                }
                                Err(ValidationError::UnsupportedFileType(msg)) => {
                                    if config.debug {
                                        println!(
                                            "⚠️  Unsupported file type: {}",
                                            file_path.display()
                                        );
                                        println!("   Reason: {}", msg);
                                    }
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::InvalidFileHeader(msg)) => {
                                    if config.debug {
                                        println!("❌ Invalid file: {}", file_path.display());
                                        println!("   Reason: {}", msg);
                                    }
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::IoError(msg)) => {
                                    if config.debug {
                                        println!(
                                            "❌ IO Error reading file: {}",
                                            file_path.display()
                                        );
                                        println!("   Reason: {}", msg);
                                    }
                                    // Don't add to matched_files - filter it out
                                }
                            }
                        } else {
                            // No validation - just add the file
                            matched_files.push(file_path);
                        }
                        break; // Don't check other patterns for the same file
                    }
                }
            } else if file_type.is_dir() {
                // Recursively search subdirectories
                let _ = self.search_recursive(&entry.path(), patterns, matched_files, config);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, create_dir};
    use tempfile::tempdir;

    #[test]
    fn test_parse_config_valid() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path().to_string_lossy();

        let config =
            FileFinder::parse_config(&temp_path, "*.txt,*.rs", false, false, false).unwrap();
        assert_eq!(config.patterns.len(), 2);
        assert!(!config.recursive);
    }

    #[test]
    fn test_parse_config_invalid_directory() {
        let result =
            FileFinder::parse_config("/nonexistent/directory", "*.txt", false, false, false);
        assert!(matches!(result, Err(SearchError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_parse_config_invalid_pattern() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path().to_string_lossy();

        let result = FileFinder::parse_config(&temp_path, "[invalid", false, false, false);
        assert!(matches!(result, Err(SearchError::InvalidPattern(_))));
    }

    #[test]
    fn test_directory_search() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        File::create(temp_path.join("test.txt")).unwrap();
        File::create(temp_path.join("example.rs")).unwrap();
        File::create(temp_path.join("data.csv")).unwrap();
        File::create(temp_path.join("test_file.log")).unwrap();

        let finder = FileFinder::new();
        let config = FileFinder::parse_config(
            &temp_path.to_string_lossy(),
            "*.txt,*.rs,test_*",
            false,
            false,
            false,
        )
        .unwrap();

        let matched_files = finder.search(&config).unwrap();
        assert_eq!(matched_files.len(), 3); // test.txt, example.rs, test_file.log
    }

    #[test]
    fn test_recursive_search() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create subdirectory
        let sub_dir = temp_path.join("subdir");
        create_dir(&sub_dir).unwrap();

        // Create nested subdirectory
        let nested_dir = sub_dir.join("nested");
        create_dir(&nested_dir).unwrap();

        // Create test files in different directories
        File::create(temp_path.join("root.txt")).unwrap();
        File::create(temp_path.join("root.rs")).unwrap();
        File::create(sub_dir.join("sub.txt")).unwrap();
        File::create(nested_dir.join("nested.txt")).unwrap();
        File::create(nested_dir.join("other.log")).unwrap();

        let finder = FileFinder::new();
        let config =
            FileFinder::parse_config(&temp_path.to_string_lossy(), "*.txt", true, false, false)
                .unwrap();

        let matched_files = finder.search(&config).unwrap();
        assert_eq!(matched_files.len(), 3); // root.txt, sub.txt, nested.txt
    }
}
