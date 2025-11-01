//! Test utilities for creating temporary directories
//!
//! This module provides a custom `TempDir` implementation using only `std::fs`
//! to avoid external dependencies and reduce supply chain attack surface.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Counter for generating unique directory names
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temporary directory that is automatically deleted when dropped
///
/// This is a minimal implementation using only `std::fs` to avoid
/// external dependencies. It provides similar functionality to
/// `tempfile::TempDir` but with no external crates.
///
/// # Example
///
/// ```no_run
/// use veraaudit::test_utils::TempDir;
///
/// let temp_dir = TempDir::new().unwrap();
/// let temp_path = temp_dir.path();
/// // Use temp_path for testing
/// // Directory is automatically cleaned up when temp_dir is dropped
/// ```
pub struct TempDir {
    path: PathBuf,
    /// Whether to skip cleanup (for debugging)
    persist: bool,
}

impl TempDir {
    /// Create a new temporary directory
    ///
    /// The directory is created in the system's temporary directory
    /// with a unique name based on process ID, timestamp, and counter.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created after 100 attempts
    pub fn new() -> io::Result<Self> {
        Self::create_with_prefix("rust_test")
    }

    /// Create a temporary directory with a custom prefix
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created
    fn create_with_prefix(prefix: &str) -> io::Result<Self> {
        let base_dir = env::temp_dir();

        // Try up to 100 times to create a unique directory
        for _ in 0..100 {
            let unique_name = Self::generate_unique_name(prefix);
            let temp_path = base_dir.join(unique_name);

            // Try to create directory - will fail if already exists
            match Self::create_dir_secure(&temp_path) {
                Ok(()) => {
                    return Ok(Self {
                        path: temp_path,
                        persist: false,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // Rare collision, try again
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::other(
            "Failed to create unique temporary directory after 100 attempts",
        ))
    }

    /// Generate a unique directory name
    ///
    /// Uses process ID, nanosecond timestamp, and atomic counter
    /// to minimize collision probability
    fn generate_unique_name(prefix: &str) -> String {
        let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();

        format!("{}_{}_{:016x}_{}", prefix, pid, nanos, counter)
    }

    /// Create directory with secure permissions
    ///
    /// On Unix, sets permissions to 0o700 (owner read/write/execute only)
    /// On Windows, uses default secure permissions
    #[cfg(unix)]
    fn create_dir_secure(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700); // rwx------ (owner only)
        builder.create(path)
    }

    #[cfg(not(unix))]
    fn create_dir_secure(path: &Path) -> io::Result<()> {
        // Windows: directories are created with appropriate ACLs by default
        fs::create_dir(path)
    }

    /// Get the path to the temporary directory
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist the directory (don't clean up on drop)
    ///
    /// Returns the path to the directory
    #[allow(dead_code)]
    pub fn into_path(mut self) -> PathBuf {
        self.persist = true;
        self.path.clone()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !self.persist {
            // Best effort cleanup - ignore errors
            // Tests may fail and leave directories, but we don't want
            // to panic in Drop which could mask the real test failure
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))]
    use std::fs::File;

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))] // Skip in Miri due to filesystem isolation
    fn test_temp_dir_creation() {
        let temp_dir = TempDir::new().unwrap();
        assert!(temp_dir.path().exists());
        assert!(temp_dir.path().is_dir());
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))] // Skip in Miri due to filesystem isolation
    fn test_temp_dir_cleanup() {
        let path = {
            let temp_dir = TempDir::new().unwrap();
            let path = temp_dir.path().to_path_buf();

            // Create a file
            File::create(path.join("test.txt")).unwrap();
            assert!(path.join("test.txt").exists());

            path
        }; // temp_dir dropped here

        // Directory should be cleaned up
        assert!(!path.exists());
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))] // Skip in Miri due to filesystem isolation
    fn test_temp_dir_persist() {
        let path = {
            let temp_dir = TempDir::new().unwrap();
            let path = temp_dir.path().to_path_buf();

            File::create(path.join("test.txt")).unwrap();

            temp_dir.into_path()
        }; // temp_dir NOT dropped (persisted)

        // Directory should still exist
        assert!(path.exists());

        // Manual cleanup
        fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    #[cfg(any(not(miri), feature = "disable-miri-isolation"))] // Skip in Miri due to filesystem isolation
    fn test_unique_directories() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();

        assert_ne!(dir1.path(), dir2.path());
    }

    #[test]
    #[cfg(all(unix, not(miri)))] // Skip in Miri due to filesystem isolation
    fn test_unix_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let metadata = fs::metadata(temp_dir.path()).unwrap();
        let permissions = metadata.permissions();

        // Should be 0o700 (owner only)
        assert_eq!(permissions.mode() & 0o777, 0o700);
    }
}
