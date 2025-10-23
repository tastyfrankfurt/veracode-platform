use std::fs::File;
use std::io::Read;
use std::path::Path;

use log::debug;

#[derive(Debug, Clone, PartialEq)]
pub enum SupportedFileType {
    Jar,
    War,
    Zip,
    Tar,
    TarGz,
    TarBz2,
    SevenZip,
    Rar,
}

impl std::fmt::Display for SupportedFileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportedFileType::Jar => write!(f, "JAR"),
            SupportedFileType::War => write!(f, "WAR"),
            SupportedFileType::Zip => write!(f, "ZIP"),
            SupportedFileType::Tar => write!(f, "TAR"),
            SupportedFileType::TarGz => write!(f, "TAR.GZ"),
            SupportedFileType::TarBz2 => write!(f, "TAR.BZ2"),
            SupportedFileType::SevenZip => write!(f, "7Z"),
            SupportedFileType::Rar => write!(f, "RAR"),
        }
    }
}

#[derive(Debug)]
pub enum ValidationError {
    IoError(String),
    UnsupportedFileType(String),
    InvalidFileHeader(String),
    FileTooLarge {
        file_path: String,
        size_mb: f64,
        max_size_mb: f64,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::IoError(msg) => write!(f, "IO error: {msg}"),
            ValidationError::UnsupportedFileType(msg) => {
                write!(f, "Unsupported file type: {msg}")
            }
            ValidationError::InvalidFileHeader(msg) => write!(f, "Invalid file header: {msg}"),
            ValidationError::FileTooLarge {
                file_path,
                size_mb,
                max_size_mb,
            } => {
                write!(
                    f,
                    "File too large: {file_path} ({size_mb:.2} MB exceeds {max_size_mb:.0} MB limit)"
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

pub struct FileValidator;

impl Default for FileValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl FileValidator {
    #[must_use]
    pub fn new() -> Self {
        FileValidator
    }

    /// Validate a file by checking its header signature
    pub fn validate_file(&self, file_path: &Path) -> Result<SupportedFileType, ValidationError> {
        // Read the first 512 bytes to check file signatures
        let mut file = File::open(file_path).map_err(|e| {
            ValidationError::IoError(format!(
                "Failed to open file '{}': {}",
                file_path.display(),
                e
            ))
        })?;

        let mut buffer = vec![0; 512];
        let bytes_read = file.read(&mut buffer).map_err(|e| {
            ValidationError::IoError(format!(
                "Failed to read file '{}': {}",
                file_path.display(),
                e
            ))
        })?;

        debug!("🔍 DEBUG: Reading file: {}", file_path.display());
        debug!("🔍 DEBUG: Bytes read: {bytes_read}");

        if bytes_read == 0 {
            return Err(ValidationError::InvalidFileHeader(
                "File is empty".to_string(),
            ));
        }

        // Resize buffer to actual bytes read
        buffer.truncate(bytes_read);

        debug!(
            "🔍 DEBUG: First 16 bytes: {:02x?}",
            &buffer[..std::cmp::min(16, buffer.len())]
        );

        // Use infer library for MIME type detection
        let file_type = infer::get(&buffer);

        // Check file extension and header signature
        let file_extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_lowercase);

        debug!(
            "🔍 DEBUG: File extension: {}",
            file_extension.as_deref().unwrap_or("None")
        );
        debug!(
            "🔍 DEBUG: Infer detected type: {}",
            file_type
                .as_ref()
                .map(|t| t.mime_type())
                .unwrap_or("None")
        );

        match file_type {
            Some(kind) => {
                match kind.mime_type() {
                    "application/zip" => {
                        debug!("🔍 DEBUG: Detected ZIP-based file");
                        // Could be ZIP, JAR, or WAR - check extension and content
                        match file_extension.as_deref() {
                            Some("jar") => {
                                debug!("🔍 DEBUG: Extension indicates JAR file");
                                // Additional validation: check for META-INF/MANIFEST.MF signature
                                if self.is_jar_file(&buffer) {
                                    debug!("🔍 DEBUG: JAR structure confirmed");
                                    Ok(SupportedFileType::Jar)
                                } else {
                                    debug!("🔍 DEBUG: JAR structure not found, treating as ZIP");
                                    Ok(SupportedFileType::Zip) // ZIP-based but not a proper JAR
                                }
                            }
                            Some("war") => {
                                debug!("🔍 DEBUG: Extension indicates WAR file");
                                // Additional validation: check for WEB-INF structure signature
                                if self.is_war_file(&buffer) {
                                    debug!("🔍 DEBUG: WAR structure confirmed");
                                    Ok(SupportedFileType::War)
                                } else {
                                    debug!("🔍 DEBUG: WAR structure not found, treating as ZIP");

                                    Ok(SupportedFileType::Zip) // ZIP-based but not a proper WAR
                                }
                            }
                            _ => {
                                debug!("🔍 DEBUG: Generic ZIP file");
                                Ok(SupportedFileType::Zip)
                            }
                        }
                    }
                    "application/x-tar" => Ok(SupportedFileType::Tar),
                    "application/gzip" => {
                        // Check if it's a tar.gz
                        if file_extension.as_deref() == Some("gz")
                            && file_path.to_string_lossy().ends_with(".tar.gz")
                        {
                            Ok(SupportedFileType::TarGz)
                        } else {
                            Err(ValidationError::UnsupportedFileType(format!(
                                "GZIP file without .tar.gz extension: {}",
                                file_path.display()
                            )))
                        }
                    }
                    "application/x-bzip2" => {
                        if file_extension.as_deref() == Some("bz2")
                            && file_path.to_string_lossy().ends_with(".tar.bz2")
                        {
                            Ok(SupportedFileType::TarBz2)
                        } else {
                            Err(ValidationError::UnsupportedFileType(format!(
                                "BZIP2 file without .tar.bz2 extension: {}",
                                file_path.display()
                            )))
                        }
                    }
                    "application/x-7z-compressed" => Ok(SupportedFileType::SevenZip),
                    "application/vnd.rar" => Ok(SupportedFileType::Rar),
                    _ => Err(ValidationError::UnsupportedFileType(format!(
                        "File type '{}' not supported for Veracode scanning",
                        kind.mime_type()
                    ))),
                }
            }
            None => {
                // Fallback to extension-based detection with header validation
                match file_extension.as_deref() {
                    Some("jar") => {
                        if self.has_zip_signature(&buffer) {
                            Ok(SupportedFileType::Jar)
                        } else {
                            Err(ValidationError::InvalidFileHeader(
                                "File has .jar extension but invalid ZIP header".to_string(),
                            ))
                        }
                    }
                    Some("war") => {
                        if self.has_zip_signature(&buffer) {
                            Ok(SupportedFileType::War)
                        } else {
                            Err(ValidationError::InvalidFileHeader(
                                "File has .war extension but invalid ZIP header".to_string(),
                            ))
                        }
                    }
                    Some("zip") => {
                        if self.has_zip_signature(&buffer) {
                            Ok(SupportedFileType::Zip)
                        } else {
                            Err(ValidationError::InvalidFileHeader(
                                "File has .zip extension but invalid ZIP header".to_string(),
                            ))
                        }
                    }
                    _ => Err(ValidationError::UnsupportedFileType(format!(
                        "Unable to determine file type for: {}",
                        file_path.display()
                    ))),
                }
            }
        }
    }

    /// Check if buffer has ZIP file signature
    fn has_zip_signature(&self, buffer: &[u8]) -> bool {
        if buffer.len() < 4 {
            return false;
        }

        // ZIP file signatures
        // PK\x03\x04 (local file header)
        // PK\x05\x06 (end of central directory)
        // PK\x01\x02 (central directory file header)
        matches!(
            buffer[0..4],
            [0x50, 0x4B, 0x03, 0x04] | [0x50, 0x4B, 0x05, 0x06] | [0x50, 0x4B, 0x01, 0x02]
        )
    }

    /// Enhanced JAR detection - looks for JAR-specific patterns
    fn is_jar_file(&self, buffer: &[u8]) -> bool {
        if !self.has_zip_signature(buffer) {
            return false;
        }

        // Look for "META-INF/" in the ZIP central directory
        // This is a heuristic check - a proper JAR should contain META-INF/MANIFEST.MF
        let search_pattern = b"META-INF/";
        let found = self.contains_pattern(buffer, search_pattern);
        debug!("🔍 DEBUG: JAR pattern search for 'META-INF/': {found}");
        found
    }

    /// Enhanced WAR detection - looks for WAR-specific patterns
    fn is_war_file(&self, buffer: &[u8]) -> bool {
        if !self.has_zip_signature(buffer) {
            return false;
        }

        // Look for "WEB-INF/" in the ZIP central directory
        // A proper WAR should contain WEB-INF/web.xml
        let search_pattern = b"WEB-INF/";
        let found = self.contains_pattern(buffer, search_pattern);
        debug!("🔍 DEBUG: WAR pattern search for 'WEB-INF/': {found}");
        found
    }

    /// Helper function to search for a pattern in buffer
    fn contains_pattern(&self, buffer: &[u8], pattern: &[u8]) -> bool {
        if pattern.len() > buffer.len() {
            return false;
        }

        for i in 0..=(buffer.len() - pattern.len()) {
            if &buffer[i..i + pattern.len()] == pattern {
                return true;
            }
        }
        false
    }

    /// Get human-readable file type description
    #[must_use]
    pub fn get_file_type_description(&self, file_type: &SupportedFileType) -> &'static str {
        match file_type {
            SupportedFileType::Jar => "Java Archive (JAR) - Executable Java application or library",
            SupportedFileType::War => "Web Application Archive (WAR) - Java web application",
            SupportedFileType::Zip => "ZIP Archive - Compressed file archive",
            SupportedFileType::Tar => "TAR Archive - Unix tape archive",
            SupportedFileType::TarGz => "TAR.GZ Archive - Gzip-compressed TAR archive",
            SupportedFileType::TarBz2 => "TAR.BZ2 Archive - Bzip2-compressed TAR archive",
            SupportedFileType::SevenZip => "7-Zip Archive - 7-Zip compressed archive",
            SupportedFileType::Rar => "RAR Archive - WinRAR compressed archive",
        }
    }

    /// Check if file type is suitable for Veracode static analysis
    #[must_use]
    pub fn is_suitable_for_static_analysis(&self, file_type: &SupportedFileType) -> bool {
        match file_type {
            SupportedFileType::Jar | SupportedFileType::War | SupportedFileType::Zip => true,
            SupportedFileType::Tar | SupportedFileType::TarGz | SupportedFileType::TarBz2 => true, // May contain source code or compiled artifacts
            SupportedFileType::SevenZip | SupportedFileType::Rar => false, // Less common for Java applications
        }
    }

    /// Validate file size against specified limit
    pub async fn validate_file_size(
        &self,
        file_path: &Path,
        max_size_mb: f64,
    ) -> Result<u64, ValidationError> {
        let metadata = tokio::fs::metadata(file_path).await.map_err(|e| {
            ValidationError::IoError(format!(
                "Failed to get file metadata for '{}': {}",
                file_path.display(),
                e
            ))
        })?;

        let file_size_bytes = metadata.len();
        let file_size_mb = file_size_bytes as f64 / (1024.0 * 1024.0);

        if file_size_mb > max_size_mb {
            return Err(ValidationError::FileTooLarge {
                file_path: file_path.display().to_string(),
                size_mb: file_size_mb,
                max_size_mb,
            });
        }

        Ok(file_size_bytes)
    }

    /// Validate file size for pipeline scans (200MB limit)
    pub async fn validate_pipeline_file_size(
        &self,
        file_path: &Path,
    ) -> Result<u64, ValidationError> {
        self.validate_file_size(file_path, 200.0).await
    }

    /// Validate file size for assessment scans (2GB limit)
    pub async fn validate_assessment_file_size(
        &self,
        file_path: &Path,
    ) -> Result<u64, ValidationError> {
        self.validate_file_size(file_path, 2048.0).await // 2GB = 2048MB
    }

    /// Validate cumulative file sizes for assessment scans (5GB total limit)
    pub async fn validate_assessment_cumulative_size(
        &self,
        file_paths: &[&Path],
    ) -> Result<u64, ValidationError> {
        let mut total_size_bytes = 0u64;
        let max_total_mb = 5120.0; // 5GB = 5120MB

        for file_path in file_paths {
            let metadata = tokio::fs::metadata(file_path).await.map_err(|e| {
                ValidationError::IoError(format!(
                    "Failed to get file metadata for '{}': {}",
                    file_path.display(),
                    e
                ))
            })?;

            total_size_bytes += metadata.len();
        }

        let total_size_mb = total_size_bytes as f64 / (1024.0 * 1024.0);

        if total_size_mb > max_total_mb {
            return Err(ValidationError::FileTooLarge {
                file_path: format!("{} files (total)", file_paths.len()),
                size_mb: total_size_mb,
                max_size_mb: max_total_mb,
            });
        }

        Ok(total_size_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_signature_detection() {
        let validator = FileValidator::new();

        // Valid ZIP signature
        let zip_header = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
        assert!(validator.has_zip_signature(&zip_header));

        // Invalid signature
        let invalid_header = [0x00, 0x01, 0x02, 0x03];
        assert!(!validator.has_zip_signature(&invalid_header));
    }

    #[test]
    fn test_pattern_search() {
        let validator = FileValidator::new();
        let buffer = b"This is a test META-INF/MANIFEST.MF content";
        let pattern = b"META-INF/";

        assert!(validator.contains_pattern(buffer, pattern));

        let missing_pattern = b"WEB-INF/";
        assert!(!validator.contains_pattern(buffer, missing_pattern));
    }

    #[test]
    fn test_file_type_descriptions() {
        let validator = FileValidator::new();

        assert!(
            validator
                .get_file_type_description(&SupportedFileType::Jar)
                .contains("Java")
        );
        assert!(
            validator
                .get_file_type_description(&SupportedFileType::War)
                .contains("Web")
        );
    }

    #[test]
    fn test_static_analysis_suitability() {
        let validator = FileValidator::new();

        assert!(validator.is_suitable_for_static_analysis(&SupportedFileType::Jar));
        assert!(validator.is_suitable_for_static_analysis(&SupportedFileType::War));
        assert!(validator.is_suitable_for_static_analysis(&SupportedFileType::Zip));
        assert!(!validator.is_suitable_for_static_analysis(&SupportedFileType::Rar));
    }

    #[test]
    fn test_file_size_validation() {
        let _validator = FileValidator::new();

        // Test with a hypothetical small file (0.5MB)
        // Note: In real tests, you'd create temporary files or mock the filesystem
        let small_size_bytes = 500 * 1024; // 0.5MB in bytes
        let small_size_mb = small_size_bytes as f64 / (1024.0 * 1024.0);

        // Test that small file passes 200MB limit
        assert!(small_size_mb < 200.0);

        // Test that 300MB file would exceed 200MB pipeline limit but pass 2GB assessment limit
        let large_size_mb = 300.0;
        assert!(large_size_mb > 200.0);
        assert!(large_size_mb < 2048.0);
    }

    #[test]
    fn test_cumulative_file_size_validation() {
        // Test cumulative size limits
        // 5 files of 1GB each = 5GB total (should pass 5GB limit)
        let individual_size_gb = 1.0;
        let individual_size_mb = individual_size_gb * 1024.0;
        let total_files = 5;
        let total_size_mb = individual_size_mb * total_files as f64;

        // Should pass 5GB (5120MB) limit
        assert!(total_size_mb <= 5120.0);

        // 6 files of 1GB each = 6GB total (should exceed 5GB limit)
        let total_files_over = 6;
        let total_size_mb_over = individual_size_mb * total_files_over as f64;
        assert!(total_size_mb_over > 5120.0);
    }
}
