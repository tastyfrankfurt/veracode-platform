use crate::filevalidator::{FileValidator, ValidationError};
use glob::Pattern;
use std::fs;
use std::path::{Path, PathBuf};

use log::{debug, error, info};

#[derive(Debug, Clone)]
pub struct SearchConfig {
    pub directory: PathBuf,
    pub patterns: Vec<Pattern>,
    pub recursive: bool,
    pub validate_files: bool,
    /// Maximum recursion depth for directory traversal (default: 100)
    /// Prevents stack overflow from deeply nested directories or symlink loops
    pub max_depth: usize,
}

#[derive(Debug)]
pub enum SearchError {
    InvalidPattern(String),
    DirectoryNotFound(String),
    NotADirectory(String),
    IoError(String),
    MaxDepthExceeded { path: String, max_depth: usize },
}

impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchError::InvalidPattern(msg) => write!(f, "Invalid pattern: {msg}"),
            SearchError::DirectoryNotFound(msg) => write!(f, "Directory not found: {msg}"),
            SearchError::NotADirectory(msg) => write!(f, "Not a directory: {msg}"),
            SearchError::IoError(msg) => write!(f, "IO error: {msg}"),
            SearchError::MaxDepthExceeded { path, max_depth } => {
                write!(
                    f,
                    "Maximum recursion depth ({max_depth}) exceeded at: {path}"
                )
            }
        }
    }
}

impl std::error::Error for SearchError {}

pub struct FileFinder {
    validator: FileValidator,
}

impl Default for FileFinder {
    fn default() -> Self {
        Self::new()
    }
}

impl FileFinder {
    #[must_use]
    pub fn new() -> Self {
        FileFinder {
            validator: FileValidator::new(),
        }
    }

    /// Parses and validates search configuration from raw parameters.
    ///
    /// The configuration includes a default `max_depth` of 100 to prevent stack overflow
    /// from deeply nested directories or symlink loops.
    ///
    /// # Errors
    ///
    /// Returns `SearchError::DirectoryNotFound` if the directory does not exist.
    /// Returns `SearchError::NotADirectory` if the path exists but is not a directory.
    /// Returns `SearchError::InvalidPattern` if any pattern has invalid glob syntax or if no valid patterns are provided.
    pub fn parse_config(
        directory: &str,
        patterns_str: &str,
        recursive: bool,
        validate_files: bool,
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
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|pattern| {
                Pattern::new(pattern)
                    .map_err(|e| SearchError::InvalidPattern(format!("'{pattern}': {e}")))
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
            max_depth: 100, // Default: prevent stack overflow from deeply nested directories
        })
    }

    /// Searches for files matching the configured patterns.
    ///
    /// Symlinks are not followed to prevent path traversal and infinite loops.
    /// Recursive searches enforce a maximum depth limit (default: 100) to prevent
    /// stack overflow from deeply nested directory structures.
    ///
    /// # Errors
    ///
    /// Returns `SearchError::IoError` if reading the directory or directory entries fails.
    /// Returns `SearchError::MaxDepthExceeded` if the recursion depth exceeds the configured limit.
    pub fn search(&self, config: &SearchConfig) -> Result<Vec<PathBuf>, SearchError> {
        let mut matched_files = Vec::new();

        if config.recursive {
            self.search_recursive(
                &config.directory,
                &config.patterns,
                &mut matched_files,
                config,
                0, // Start at depth 0
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
            let entry = entry
                .map_err(|e| SearchError::IoError(format!("Error reading directory entry: {e}")))?;

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    error!(
                        "Warning: Could not determine file type for {}: {}",
                        entry.path().display(),
                        e
                    );
                    continue;
                }
            };

            // Skip symlinks - they are not followed to prevent loops and path traversal
            if file_type.is_symlink() {
                debug!(
                    "Skipping symlink: {} (symlinks are not followed)",
                    entry.path().display()
                );
                continue;
            }

            if file_type.is_file() {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                // Check if the filename matches any of the patterns
                for pattern in patterns {
                    if pattern.matches(&file_name_str) {
                        let file_path = entry.path();

                        // Validate file if validation is enabled
                        if config.validate_files {
                            match self.validator.validate_file(&file_path) {
                                Ok(file_type) => {
                                    let suitable =
                                        self.validator.is_suitable_for_static_analysis(&file_type);
                                    debug!("✅ Valid file: {}", file_path.display());
                                    debug!(
                                        "   Type: {} ({})",
                                        file_type,
                                        self.validator.get_file_type_description(&file_type)
                                    );
                                    debug!(
                                        "   Static Analysis: {}",
                                        if suitable {
                                            "✅ Suitable"
                                        } else {
                                            "❌ Not recommended"
                                        }
                                    );
                                    info!("✅ Valid file: {}", file_path.display());
                                    matched_files.push(file_path);
                                }
                                Err(ValidationError::UnsupportedFileType(msg)) => {
                                    debug!("⚠️  Unsupported file type: {}", file_path.display());
                                    debug!("   Reason: {msg}");
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::InvalidFileHeader(msg)) => {
                                    debug!("❌ Invalid file: {}", file_path.display());
                                    debug!("   Reason: {msg}");
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::IoError(msg)) => {
                                    debug!("❌ IO Error reading file: {}", file_path.display());
                                    debug!("   Reason: {msg}");
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::FileTooLarge {
                                    file_path: _,
                                    size_mb,
                                    max_size_mb,
                                }) => {
                                    debug!("⚠️  File too large: {}", file_path.display());
                                    debug!(
                                        "   Size: {size_mb:.2} MB exceeds {max_size_mb:.0} MB limit"
                                    );
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
        current_depth: usize,
    ) -> Result<(), SearchError> {
        // Check if we've exceeded maximum recursion depth
        if current_depth >= config.max_depth {
            return Err(SearchError::MaxDepthExceeded {
                path: dir_path.display().to_string(),
                max_depth: config.max_depth,
            });
        }

        let entries = match fs::read_dir(dir_path) {
            Ok(entries) => entries,
            Err(e) => {
                error!(
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
                    error!("Warning: Error reading directory entry: {e}");
                    continue;
                }
            };

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    error!(
                        "Warning: Could not determine file type for {}: {}",
                        entry.path().display(),
                        e
                    );
                    continue;
                }
            };

            // Skip symlinks - they are not followed to prevent loops and path traversal
            if file_type.is_symlink() {
                debug!(
                    "Skipping symlink: {} (symlinks are not followed)",
                    entry.path().display()
                );
                continue;
            }

            if file_type.is_file() {
                let file_name = entry.file_name();
                let file_name_str = file_name.to_string_lossy();

                // Check if the filename matches any of the patterns
                for pattern in patterns {
                    if pattern.matches(&file_name_str) {
                        let file_path = entry.path();

                        // Validate file if validation is enabled
                        if config.validate_files {
                            match self.validator.validate_file(&file_path) {
                                Ok(file_type) => {
                                    let suitable =
                                        self.validator.is_suitable_for_static_analysis(&file_type);
                                    debug!("✅ Valid file: {}", file_path.display());
                                    debug!(
                                        "   Type: {} ({})",
                                        file_type,
                                        self.validator.get_file_type_description(&file_type)
                                    );
                                    debug!(
                                        "   Static Analysis: {}",
                                        if suitable {
                                            "✅ Suitable"
                                        } else {
                                            "❌ Not recommended"
                                        }
                                    );
                                    info!("✅ Valid file: {}", file_path.display());
                                    matched_files.push(file_path);
                                }
                                Err(ValidationError::UnsupportedFileType(msg)) => {
                                    debug!("⚠️  Unsupported file type: {}", file_path.display());
                                    debug!("   Reason: {msg}");
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::InvalidFileHeader(msg)) => {
                                    debug!("❌ Invalid file: {}", file_path.display());
                                    debug!("   Reason: {msg}");
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::IoError(msg)) => {
                                    debug!("❌ IO Error reading file: {}", file_path.display());
                                    debug!("   Reason: {msg}");
                                    // Don't add to matched_files - filter it out
                                }
                                Err(ValidationError::FileTooLarge {
                                    file_path: _,
                                    size_mb,
                                    max_size_mb,
                                }) => {
                                    debug!("⚠️  File too large: {}", file_path.display());
                                    debug!(
                                        "   Size: {size_mb:.2} MB exceeds {max_size_mb:.0} MB limit"
                                    );
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
                if let Err(e) = self.search_recursive(
                    &entry.path(),
                    patterns,
                    matched_files,
                    config,
                    current_depth.saturating_add(1),
                ) {
                    // Log errors from recursive calls but continue with other directories
                    error!(
                        "Warning: Failed to search subdirectory '{}': {}",
                        entry.path().display(),
                        e
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use super::*;
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use crate::test_utils::TempDir;
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use std::fs::{File, create_dir};

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_parse_config_valid() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path().to_string_lossy();

        let config = FileFinder::parse_config(&temp_path, "*.txt,*.rs", false, false)
            .expect("should parse config");
        assert_eq!(config.patterns.len(), 2);
        assert!(!config.recursive);
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_parse_config_invalid_directory() {
        let result = FileFinder::parse_config("/nonexistent/directory", "*.txt", false, false);
        assert!(matches!(result, Err(SearchError::DirectoryNotFound(_))));
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_parse_config_invalid_pattern() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path().to_string_lossy();

        let result = FileFinder::parse_config(&temp_path, "[invalid", false, false);
        assert!(matches!(result, Err(SearchError::InvalidPattern(_))));
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_directory_search() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create test files
        File::create(temp_path.join("test.txt")).expect("should create test.txt");
        File::create(temp_path.join("example.rs")).expect("should create example.rs");
        File::create(temp_path.join("data.csv")).expect("should create data.csv");
        File::create(temp_path.join("test_file.log")).expect("should create test_file.log");

        let finder = FileFinder::new();
        let config = FileFinder::parse_config(
            &temp_path.to_string_lossy(),
            "*.txt,*.rs,test_*",
            false,
            false,
        )
        .expect("should parse config");

        let matched_files = finder.search(&config).expect("should search files");
        assert_eq!(matched_files.len(), 3); // test.txt, example.rs, test_file.log
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_recursive_search() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path();

        // Create subdirectory
        let sub_dir = temp_path.join("subdir");
        create_dir(&sub_dir).expect("should create subdir");

        // Create nested subdirectory
        let nested_dir = sub_dir.join("nested");
        create_dir(&nested_dir).expect("should create nested dir");

        // Create test files in different directories
        File::create(temp_path.join("root.txt")).expect("should create root.txt");
        File::create(temp_path.join("root.rs")).expect("should create root.rs");
        File::create(sub_dir.join("sub.txt")).expect("should create sub.txt");
        File::create(nested_dir.join("nested.txt")).expect("should create nested.txt");
        File::create(nested_dir.join("other.log")).expect("should create other.log");

        let finder = FileFinder::new();
        let config = FileFinder::parse_config(&temp_path.to_string_lossy(), "*.txt", true, false)
            .expect("should parse config");

        let matched_files = finder.search(&config).expect("should search files");
        assert_eq!(matched_files.len(), 3); // root.txt, sub.txt, nested.txt
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_max_depth_exceeded() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path().to_string_lossy();

        // Create a config with max_depth = 0
        // This means the search cannot even start (current_depth=0 >= max_depth=0)
        let mut config = FileFinder::parse_config(&temp_path, "*.txt", true, false)
            .expect("should parse config");
        config.max_depth = 0;

        let finder = FileFinder::new();
        let result = finder.search(&config);

        // Should fail immediately with MaxDepthExceeded
        assert!(matches!(result, Err(SearchError::MaxDepthExceeded { .. })));
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_parse_config_empty_patterns() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let temp_path = temp_dir.path().to_string_lossy();

        // Test with only whitespace/commas
        let result = FileFinder::parse_config(&temp_path, "  ,  , ", false, false);
        assert!(matches!(result, Err(SearchError::InvalidPattern(_))));

        // Test with empty string
        let result = FileFinder::parse_config(&temp_path, "", false, false);
        assert!(matches!(result, Err(SearchError::InvalidPattern(_))));
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    fn test_parse_config_not_a_directory() {
        let temp_dir = TempDir::new().expect("should create temp dir");
        let file_path = temp_dir.path().join("test.txt");
        File::create(&file_path).expect("should create test file");

        let result = FileFinder::parse_config(&file_path.to_string_lossy(), "*.txt", false, false);
        assert!(matches!(result, Err(SearchError::NotADirectory(_))));
    }
}

#[cfg(all(test, not(miri)))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod proptest_tests {
    use super::*;
    use crate::test_utils::TempDir;
    use proptest::prelude::*;
    use std::fs::{File, create_dir_all};

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: if cfg!(miri) { 10 } else { 1000 },
            failure_persistence: None,
            .. ProptestConfig::default()
        })]

        /// Property: parse_config should handle arbitrary pattern strings without panicking
        /// Security: Tests input validation and prevents DoS via malformed patterns
        #[test]
        fn prop_parse_config_no_panic(
            pattern in "[a-zA-Z0-9*?.,_ -]{0,100}",
            recursive in any::<bool>(),
            validate_files in any::<bool>(),
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path().to_string_lossy();

            // Should not panic - either succeeds or returns error
            let _ = FileFinder::parse_config(&temp_path, &pattern, recursive, validate_files);
        }

        /// Property: Empty patterns should always fail
        /// Security: Prevents resource exhaustion from matching all files
        #[test]
        fn prop_empty_patterns_rejected(
            whitespace in r"[ ,\t]*",
            recursive in any::<bool>(),
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path().to_string_lossy();

            let result = FileFinder::parse_config(&temp_path, &whitespace, recursive, false);

            // Empty patterns should be rejected
            if whitespace.chars().all(|c| c.is_whitespace() || c == ',') {
                prop_assert!(matches!(result, Err(SearchError::InvalidPattern(_))));
            }
        }

        /// Property: Valid patterns should create correct number of patterns
        /// Security: Validates pattern parsing logic
        #[test]
        fn prop_pattern_count_matches_input(
            pattern_count in 1usize..=10,
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path().to_string_lossy();

            // Create valid patterns
            let patterns = vec!["*.txt"; pattern_count];
            let pattern_str = patterns.join(",");

            let config = FileFinder::parse_config(&temp_path, &pattern_str, false, false)
                .expect("should parse valid patterns");

            prop_assert_eq!(config.patterns.len(), pattern_count);
        }

        /// Property: Max depth should always be set to 100 by default
        /// Security: Ensures resource exhaustion protection is always enabled
        #[test]
        fn prop_max_depth_always_set(
            pattern in "\\*\\.(txt|rs|md)",
            recursive in any::<bool>(),
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path().to_string_lossy();

            let config = FileFinder::parse_config(&temp_path, &pattern, recursive, false)
                .expect("should parse config");

            // Default max_depth should always be 100 to prevent stack overflow
            prop_assert_eq!(config.max_depth, 100);
        }

        /// Property: Nonexistent directories should always fail
        /// Security: Prevents path traversal and information disclosure
        #[test]
        fn prop_nonexistent_dir_rejected(
            random_suffix in "[a-zA-Z0-9]{1,20}",
        ) {
            let nonexistent = format!("/tmp/nonexistent_verascan_test_{random_suffix}");
            let result = FileFinder::parse_config(&nonexistent, "*.txt", false, false);

            prop_assert!(matches!(result, Err(SearchError::DirectoryNotFound(_))));
        }


        /// Property: Search should handle directories with many files
        /// Security: Tests resource exhaustion resistance
        #[test]
        fn prop_handles_many_files(
            file_count in 1usize..=50, // Limit to keep test fast
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path();

            // Create many files
            for i in 0..file_count {
                File::create(temp_path.join(format!("file_{i}.txt")))
                    .expect("should create file");
            }

            let finder = FileFinder::new();
            let config = FileFinder::parse_config(
                &temp_path.to_string_lossy(),
                "*.txt",
                false,
                false,
            ).expect("should parse config");

            let matched_files = finder.search(&config).expect("should search");
            prop_assert_eq!(matched_files.len(), file_count);
        }

        /// Property: Recursive search respects max_depth limit
        /// Security: Prevents stack overflow from deeply nested directories
        #[test]
        fn prop_max_depth_enforced(
            max_depth in 1usize..=10,
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");

            // Add a file at root level
            File::create(temp_dir.path().join("root.txt"))
                .expect("should create root file");

            // Create nested directories with files
            let mut current_path = temp_dir.path().to_path_buf();
            for level in 0..15 {
                current_path = current_path.join(format!("level_{level}"));
                create_dir_all(&current_path).expect("should create nested dir");
                File::create(current_path.join("test.txt"))
                    .expect("should create file");
            }

            let finder = FileFinder::new();
            let mut config = FileFinder::parse_config(
                &temp_dir.path().to_string_lossy(),
                "*.txt",
                true,
                false,
            ).expect("should parse config");

            config.max_depth = max_depth;

            let result = finder.search(&config);

            // Search should succeed and find files up to max_depth
            prop_assert!(result.is_ok());
            let files = result.unwrap();

            // Should find at least the root file (at depth 0)
            // and files in nested directories up to max_depth-1
            // Total: 1 (root) + max_depth (one per directory level)
            prop_assert!(!files.is_empty());
            prop_assert!(files.len() <= max_depth + 1); // +1 for root level
        }

        /// Property: Pattern matching is deterministic
        /// Security: Ensures consistent behavior
        #[test]
        fn prop_deterministic_matching(
            file_count in 1usize..=20,
            pattern in "\\*\\.(txt|rs|md|log)",
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path();

            // Create files with various extensions
            let extensions = ["txt", "rs", "md", "log", "dat"];
            for i in 0..file_count {
                let ext = extensions[i % extensions.len()];
                File::create(temp_path.join(format!("file_{i}.{ext}")))
                    .expect("should create file");
            }

            let finder = FileFinder::new();
            let config = FileFinder::parse_config(
                &temp_path.to_string_lossy(),
                &pattern,
                false,
                false,
            ).expect("should parse config");

            // Run search twice
            let result1 = finder.search(&config).expect("should search");
            let result2 = finder.search(&config).expect("should search");

            // Results should be identical
            prop_assert_eq!(&result1, &result2);

            // Verify sorted order
            for i in 1..result1.len() {
                prop_assert!(result1[i - 1] <= result1[i]);
            }
        }

        /// Property: Invalid glob patterns should be rejected
        /// Security: Prevents code injection via pattern strings
        #[test]
        fn prop_invalid_patterns_rejected(
            bracket_depth in 0usize..=10,
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path().to_string_lossy();

            // Create unbalanced bracket patterns
            let invalid_pattern = "[".repeat(bracket_depth);

            if !invalid_pattern.is_empty() {
                let result = FileFinder::parse_config(&temp_path, &invalid_pattern, false, false);
                prop_assert!(matches!(result, Err(SearchError::InvalidPattern(_))));
            }
        }

        /// Property: SearchConfig cloning preserves all fields
        /// Security: Ensures configuration integrity
        #[test]
        fn prop_config_clone_preserves_state(
            recursive in any::<bool>(),
            validate_files in any::<bool>(),
            max_depth in 1usize..=200,
        ) {
            let temp_dir = TempDir::new().expect("should create temp dir");
            let temp_path = temp_dir.path().to_string_lossy();

            let mut config = FileFinder::parse_config(&temp_path, "*.txt", recursive, validate_files)
                .expect("should parse config");
            config.max_depth = max_depth;

            let cloned = config.clone();

            prop_assert_eq!(cloned.directory, config.directory);
            prop_assert_eq!(cloned.patterns.len(), config.patterns.len());
            prop_assert_eq!(cloned.recursive, config.recursive);
            prop_assert_eq!(cloned.validate_files, config.validate_files);
            prop_assert_eq!(cloned.max_depth, config.max_depth);
        }
    }
}
