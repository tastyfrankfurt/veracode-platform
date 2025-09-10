//! Path Resolution Utilities
//!
//! This module provides functionality to resolve file paths from scan results
//! to actual project file paths, handling common source directory structures.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use log::debug;

/// Configuration for path resolution
#[derive(Debug, Clone)]
pub struct PathResolverConfig {
    pub project_dir: PathBuf,
}

impl PathResolverConfig {
    /// Create a new path resolver configuration
    pub fn new<P: AsRef<Path>>(project_dir: P) -> Self {
        let path = project_dir.as_ref();
        let absolute_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            // Convert relative path to absolute path
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
                .canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
        };

        Self {
            project_dir: absolute_path,
        }
    }
}

/// Path resolver for converting scan file paths to actual project paths
#[derive(Debug, Clone)]
pub struct PathResolver {
    config: PathResolverConfig,
}

impl PathResolver {
    /// Create a new path resolver
    #[must_use]
    pub fn new(config: PathResolverConfig) -> Self {
        Self { config }
    }

    /// Helper method to convert Path to Cow<str> efficiently
    fn path_to_cow_str(path: &Path) -> Cow<'_, str> {
        Cow::Owned(path.to_string_lossy().into_owned())
    }

    /// Resolve file path relative to project directory
    ///
    /// This function takes a file path from scan results (e.g., "com/example/vulnerable/VulnerableApp.java")
    /// and tries to resolve it to the actual project path (e.g., "src/main/java/com/example/vulnerable/VulnerableApp.java")
    ///
    /// Returns `Cow<str>` to avoid unnecessary allocations when the path doesn't need to be modified.
    #[must_use]
    pub fn resolve_file_path<'a>(&self, file_path: &'a str) -> Cow<'a, str> {
        debug!("🔍 DEBUG: Resolving file path: '{file_path}'");
        debug!(
            "   Project directory: '{}'",
            self.config.project_dir.display()
        );

        // Convert file_path to a Path
        let file_path_buf = Path::new(file_path);

        debug!(
            "   Path is_absolute: {}, is_relative: {}",
            file_path_buf.is_absolute(),
            file_path_buf.is_relative()
        );

        // PRECHECK: First check if the path is already valid before attempting discovery
        if let Some(valid_path) = self.precheck_file_validity(file_path) {
            debug!("   ✅ Precheck found valid path: '{valid_path}'");
            return valid_path;
        }

        // Handle absolute paths - try to strip project directory prefix
        if file_path_buf.is_absolute() {
            if let Ok(relative_path) = file_path_buf.strip_prefix(&self.config.project_dir) {
                let result = Self::path_to_cow_str(relative_path);
                debug!("   ✅ Stripped project prefix, result: '{result}'");
                return result;
            }
            debug!("   ⚠️  Cannot strip project prefix from absolute path");
        }

        // Handle relative paths - this is the main case for Veracode findings
        // Veracode often provides paths like: com/example/vulnerable/CryptoUtils.java
        // We need to find where this actually exists in the repository structure

        debug!("   🔍 Searching for file in project structure...");

        // Try to find the file by its full relative path first
        if let Some(found_path) = self.find_file_by_relative_path(file_path) {
            debug!("   ✅ Found by relative path search: '{found_path}'");
            return Cow::Owned(found_path);
        }

        // If that fails, try to find by filename only
        if let Some(filename) = file_path_buf.file_name().and_then(|n| n.to_str()) {
            debug!("   🔍 Searching by filename only: '{filename}'");
            if let Some(found_path) = self.find_file_in_project(filename) {
                debug!("   ✅ Found by filename search: '{found_path}'");
                return Cow::Owned(found_path);
            }
        }

        // Last resort: return the original path
        debug!("   ❌ Could not resolve path, returning original: '{file_path}'");
        Cow::Borrowed(file_path)
    }

    /// Find a file by its relative path structure within the project
    /// This handles cases like: com/example/vulnerable/CryptoUtils.java
    /// Should be found at: src/main/java/com/example/vulnerable/CryptoUtils.java
    #[must_use]
    pub fn find_file_by_relative_path(&self, relative_path: &str) -> Option<String> {
        debug!("   🔍 Searching for relative path: '{relative_path}'");

        // Common Java source directory patterns to search
        let common_source_dirs = [
            "src/main/java",
            "src/main/kotlin",
            "src/test/java",
            "src/test/kotlin",
            "src",
            "java",
            "kotlin",
            "main/java",
            "test/java",
        ];

        for source_dir in &common_source_dirs {
            let candidate_path = self.config.project_dir.join(source_dir).join(relative_path);
            debug!("     Checking exact path: {}", candidate_path.display());

            // Must check that the EXACT file exists (not just a partial match)
            if candidate_path.exists() && candidate_path.is_file() {
                // Verify this is an exact match by checking that the constructed path
                // ends with the exact relative path we're looking for
                if let Some(candidate_str) = candidate_path.to_str() {
                    // Use path separator normalization to ensure exact matching
                    let normalized_relative = relative_path.replace('\\', "/");
                    let normalized_candidate = candidate_str.replace('\\', "/");

                    if normalized_candidate.ends_with(&normalized_relative) {
                        // Additional check: ensure we're not matching a substring
                        // The character before our match should be a path separator or start of string
                        let match_start = normalized_candidate.len() - normalized_relative.len();
                        if match_start == 0
                            || normalized_candidate.chars().nth(match_start - 1) == Some('/')
                        {
                            // Return path relative to project root
                            if let Ok(result) =
                                candidate_path.strip_prefix(&self.config.project_dir)
                            {
                                let result_str = result.to_string_lossy().to_string();
                                debug!("     ✅ Found exact path match at: {result_str}");
                                return Some(result_str);
                            }
                        } else {
                            debug!(
                                "     ⚠️  Path ends with target but not at boundary: {normalized_candidate}"
                            );
                        }
                    }
                } else {
                    debug!(
                        "     ⚠️  Could not convert path to string: {}",
                        candidate_path.display()
                    );
                }
            }
        }

        // Also try the relative path directly in case it's already correct
        let direct_path = self.config.project_dir.join(relative_path);
        debug!("     Checking direct path: {}", direct_path.display());

        if direct_path.exists()
            && direct_path.is_file()
            && let Ok(result) = direct_path.strip_prefix(&self.config.project_dir)
        {
            let result_str = result.to_string_lossy().to_string();
            debug!("     ✅ Found exact direct match: {result_str}");
            return Some(result_str);
        }

        debug!("     ❌ No exact path match found in any source directories");
        None
    }

    /// Find a file by name within the project directory tree
    #[must_use]
    pub fn find_file_in_project(&self, filename: &str) -> Option<String> {
        debug!("   🔍 Recursive search for filename: '{filename}'");
        Self::search_for_file(&self.config.project_dir, filename, &self.config.project_dir)
    }

    /// Recursively search for a file by name and return its path relative to project root
    fn search_for_file(current_dir: &Path, filename: &str, project_root: &Path) -> Option<String> {
        if let Ok(entries) = std::fs::read_dir(current_dir) {
            for entry in entries.flatten() {
                let entry_path = entry.path();

                if entry_path.is_file() {
                    if let Some(entry_filename) = entry_path.file_name().and_then(|n| n.to_str())
                        && entry_filename == filename
                    {
                        // Found the file! Return its path relative to project root
                        if let Ok(relative_path) = entry_path.strip_prefix(project_root) {
                            return Some(relative_path.to_string_lossy().to_string());
                        }
                    }
                } else if entry_path.is_dir() {
                    // Recursively search subdirectories
                    if let Some(found) = Self::search_for_file(&entry_path, filename, project_root)
                    {
                        return Some(found);
                    }
                }
            }
        }
        None
    }

    /// Precheck if the file path already exists in the project directory
    ///
    /// This method simply checks if the provided file path exists as-is in the project directory
    fn precheck_file_validity<'a>(&self, file_path: &'a str) -> Option<Cow<'a, str>> {
        debug!("   🔍 Precheck: Checking if file path exists in project directory...");

        let file_path_buf = Path::new(file_path);

        // For absolute paths, check if they exist and are within project directory
        if file_path_buf.is_absolute() {
            if file_path_buf.exists() && file_path_buf.is_file() {
                debug!("   ✅ Precheck: Absolute path exists");
                // Try to make it relative to project directory if it's within the project
                if let Ok(relative_path) = file_path_buf.strip_prefix(&self.config.project_dir) {
                    return Some(Cow::Owned(relative_path.to_string_lossy().into_owned()));
                }
                // File exists but is outside project directory - return as-is
                return Some(Cow::Borrowed(file_path));
            }
        } else {
            // For relative paths, check if they exist directly under project directory
            let full_path = self.config.project_dir.join(file_path);
            if full_path.exists() && full_path.is_file() {
                debug!("   ✅ Precheck: File path exists in project directory");
                return Some(Cow::Borrowed(file_path));
            }
        }

        debug!(
            "   ❌ Precheck: File path does not exist in project directory, proceeding with discovery"
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use tempfile::tempdir;

    #[test]
    fn test_resolve_file_path_basic() {
        let temp_dir = tempdir().unwrap();
        let config = PathResolverConfig::new(temp_dir.path());
        let resolver = PathResolver::new(config);

        // Test with relative path that doesn't exist - should return original
        let result = resolver.resolve_file_path("com/example/vulnerable/CryptoUtils.java");
        assert_eq!(result, "com/example/vulnerable/CryptoUtils.java");

        // Test absolute path outside project - should return original
        let result = resolver.resolve_file_path("/absolute/path/file.java");
        assert_eq!(result, "/absolute/path/file.java");
    }

    #[test]
    fn test_find_file_by_relative_path() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create a Java-like directory structure
        let java_dir = temp_path.join("src/main/java/com/example/vulnerable");
        fs::create_dir_all(&java_dir).unwrap();

        // Create a test file
        let test_file = java_dir.join("CryptoUtils.java");
        File::create(&test_file).unwrap();

        let config = PathResolverConfig::new(temp_path);
        let resolver = PathResolver::new(config);

        // Test finding the file by its relative path
        let result = resolver.find_file_by_relative_path("com/example/vulnerable/CryptoUtils.java");
        assert_eq!(
            result,
            Some("src/main/java/com/example/vulnerable/CryptoUtils.java".to_string())
        );
    }

    #[test]
    fn test_find_file_in_project() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create nested directory structure
        let nested_dir = temp_path.join("src/main/java/com/example");
        fs::create_dir_all(&nested_dir).unwrap();

        // Create a test file
        let test_file = nested_dir.join("TestFile.java");
        File::create(&test_file).unwrap();

        let config = PathResolverConfig::new(temp_path);
        let resolver = PathResolver::new(config);

        // Test finding the file by filename
        let result = resolver.find_file_in_project("TestFile.java");
        assert_eq!(
            result,
            Some("src/main/java/com/example/TestFile.java".to_string())
        );
    }

    #[test]
    fn test_path_matching_precision() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create directory structure
        let java_dir = temp_path.join("src/main/java/com/example/vulnerable");
        fs::create_dir_all(&java_dir).unwrap();

        // Create two similar files
        File::create(java_dir.join("VulnerableApp.java")).unwrap();
        File::create(java_dir.join("SimpleVulnerableApp.java")).unwrap();

        let config = PathResolverConfig::new(temp_path);
        let resolver = PathResolver::new(config);

        // Test that "VulnerableApp.java" matches exactly, not "SimpleVulnerableApp.java"
        let result =
            resolver.find_file_by_relative_path("com/example/vulnerable/VulnerableApp.java");
        assert_eq!(
            result,
            Some("src/main/java/com/example/vulnerable/VulnerableApp.java".to_string())
        );

        // Test that "SimpleVulnerableApp.java" also matches correctly
        let result =
            resolver.find_file_by_relative_path("com/example/vulnerable/SimpleVulnerableApp.java");
        assert_eq!(
            result,
            Some("src/main/java/com/example/vulnerable/SimpleVulnerableApp.java".to_string())
        );
    }

    #[test]
    fn test_common_source_directories() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Test different source directory patterns
        let test_dirs = [
            "src/main/java",
            "src/main/kotlin",
            "src/test/java",
            "src/test/kotlin",
            "src",
            "java",
            "kotlin",
            "main/java",
            "test/java",
        ];

        for (i, source_dir) in test_dirs.iter().enumerate() {
            let full_dir = temp_path.join(source_dir).join("com/example");
            fs::create_dir_all(&full_dir).unwrap();

            let test_file = full_dir.join(format!("Test{i}.java"));
            File::create(&test_file).unwrap();

            let config = PathResolverConfig::new(temp_path);
            let resolver = PathResolver::new(config);

            let result = resolver.find_file_by_relative_path(&format!("com/example/Test{i}.java"));
            assert_eq!(
                result,
                Some(format!("{source_dir}/com/example/Test{i}.java"))
            );
        }
    }
}
