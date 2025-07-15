use std::fs::File;
use std::io::Read;
use std::path::Path;

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
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::IoError(msg) => write!(f, "IO error: {}", msg),
            ValidationError::UnsupportedFileType(msg) => {
                write!(f, "Unsupported file type: {}", msg)
            }
            ValidationError::InvalidFileHeader(msg) => write!(f, "Invalid file header: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}

pub struct FileValidator;

impl FileValidator {
    pub fn new() -> Self {
        FileValidator
    }

    /// Validate a file by checking its header signature
    pub fn validate_file(
        &self,
        file_path: &Path,
        debug: bool,
    ) -> Result<SupportedFileType, ValidationError> {
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

        if debug {
            println!("🔍 DEBUG: Reading file: {}", file_path.display());
            println!("🔍 DEBUG: Bytes read: {}", bytes_read);
        }

        if bytes_read == 0 {
            return Err(ValidationError::InvalidFileHeader(
                "File is empty".to_string(),
            ));
        }

        // Resize buffer to actual bytes read
        buffer.truncate(bytes_read);

        if debug {
            println!(
                "🔍 DEBUG: First 16 bytes: {:02x?}",
                &buffer[..std::cmp::min(16, buffer.len())]
            );
        }

        // Use infer library for MIME type detection
        let file_type = infer::get(&buffer);

        // Check file extension and header signature
        let file_extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase());

        if debug {
            println!("🔍 DEBUG: File extension: {:?}", file_extension);
            println!(
                "🔍 DEBUG: Infer detected type: {:?}",
                file_type.as_ref().map(|t| t.mime_type())
            );
        }

        match file_type {
            Some(kind) => {
                match kind.mime_type() {
                    "application/zip" => {
                        if debug {
                            println!("🔍 DEBUG: Detected ZIP-based file");
                        }
                        // Could be ZIP, JAR, or WAR - check extension and content
                        match file_extension.as_deref() {
                            Some("jar") => {
                                if debug {
                                    println!("🔍 DEBUG: Extension indicates JAR file");
                                }
                                // Additional validation: check for META-INF/MANIFEST.MF signature
                                if self.is_jar_file(&buffer, debug) {
                                    if debug {
                                        println!("🔍 DEBUG: JAR structure confirmed");
                                    }
                                    Ok(SupportedFileType::Jar)
                                } else {
                                    if debug {
                                        println!(
                                            "🔍 DEBUG: JAR structure not found, treating as ZIP"
                                        );
                                    }
                                    Ok(SupportedFileType::Zip) // ZIP-based but not a proper JAR
                                }
                            }
                            Some("war") => {
                                if debug {
                                    println!("🔍 DEBUG: Extension indicates WAR file");
                                }
                                // Additional validation: check for WEB-INF structure signature
                                if self.is_war_file(&buffer, debug) {
                                    if debug {
                                        println!("🔍 DEBUG: WAR structure confirmed");
                                    }
                                    Ok(SupportedFileType::War)
                                } else {
                                    if debug {
                                        println!(
                                            "🔍 DEBUG: WAR structure not found, treating as ZIP"
                                        );
                                    }
                                    Ok(SupportedFileType::Zip) // ZIP-based but not a proper WAR
                                }
                            }
                            _ => {
                                if debug {
                                    println!("🔍 DEBUG: Generic ZIP file");
                                }
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
    fn is_jar_file(&self, buffer: &[u8], debug: bool) -> bool {
        if !self.has_zip_signature(buffer) {
            return false;
        }

        // Look for "META-INF/" in the ZIP central directory
        // This is a heuristic check - a proper JAR should contain META-INF/MANIFEST.MF
        let search_pattern = b"META-INF/";
        let found = self.contains_pattern(buffer, search_pattern);
        if debug {
            println!("🔍 DEBUG: JAR pattern search for 'META-INF/': {}", found);
        }
        found
    }

    /// Enhanced WAR detection - looks for WAR-specific patterns
    fn is_war_file(&self, buffer: &[u8], debug: bool) -> bool {
        if !self.has_zip_signature(buffer) {
            return false;
        }

        // Look for "WEB-INF/" in the ZIP central directory
        // A proper WAR should contain WEB-INF/web.xml
        let search_pattern = b"WEB-INF/";
        let found = self.contains_pattern(buffer, search_pattern);
        if debug {
            println!("🔍 DEBUG: WAR pattern search for 'WEB-INF/': {}", found);
        }
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
    pub fn is_suitable_for_static_analysis(&self, file_type: &SupportedFileType) -> bool {
        match file_type {
            SupportedFileType::Jar | SupportedFileType::War | SupportedFileType::Zip => true,
            SupportedFileType::Tar | SupportedFileType::TarGz | SupportedFileType::TarBz2 => true, // May contain source code or compiled artifacts
            SupportedFileType::SevenZip | SupportedFileType::Rar => false, // Less common for Java applications
        }
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
}
