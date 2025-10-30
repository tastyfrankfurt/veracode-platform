//! CLI argument parsing for veraaudit
use crate::validation::{ActionType, AuditAction, Region};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "veraaudit",
    version,
    about = "Veracode audit log retrieval tool",
    long_about = "CLI tool for retrieving and archiving Veracode audit logs using the Reporting REST API",
    after_help = "IMPORTANT - VERACODE BACKEND BEHAVIOR:

Audit log data has a 2-HOUR REFRESH CYCLE. This means:
  • Data is always ~2 hours behind current time
  • Querying recent logs (< 2 hours) will return empty results
  • This is a Veracode backend limitation, not a tool issue

BEST PRACTICES:
  • Use --start-offset of at least 2-3 hours for reliable results
  • Service mode automatically handles this via chunked retrieval
  • Tool will stop early if data not yet available

EXAMPLES:
  # Query last 3 hours (ensures data availability)
  veraaudit run --start-offset 3h --interval 30m

  # Service mode handles 2-hour lag automatically
  veraaudit service --interval 15m

For more details, see README.md or run: veraaudit help-env"
)]
pub struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    pub command: Commands,

    /// Veracode region (commercial, european, federal)
    #[arg(long, default_value = "commercial", global = true, value_parser = clap::value_parser!(Region))]
    pub region: Region,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run one-time audit log retrieval (CLI mode)
    Run {
        /// Start datetime (UTC). Format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
        /// Defaults to 60 minutes before end time if not specified
        /// Cannot be used with --start-offset
        #[arg(short, long, conflicts_with = "start_offset", value_parser = validate_datetime)]
        start: Option<String>,

        /// Start offset from now. Format: Nm (minutes), Nh (hours), or Nd (days)
        /// Examples: 30m, 2h, 7d
        /// Cannot be used with --start
        #[arg(long, conflicts_with = "start", value_parser = validate_time_offset)]
        start_offset: Option<String>,

        /// End datetime (UTC). Format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
        /// Defaults to current time if not specified
        /// Cannot be used with --interval
        #[arg(short, long, conflicts_with = "interval", value_parser = validate_datetime)]
        end: Option<String>,

        /// Interval in minutes to add to start time to calculate end time
        /// Format: N (minutes), or use same format as start-offset (Nm, Nh, Nd)
        /// Examples: 15, 30m, 1h
        /// Range: 5-60 minutes
        /// Cannot be used with --end
        #[arg(short, long, conflicts_with = "end", value_parser = validate_interval)]
        interval: Option<String>,

        /// Output directory for audit log files
        #[arg(short, long, default_value = "./audit_logs", value_parser = validate_directory)]
        output_dir: String,

        /// Audit actions to filter. Valid values: Create, Delete, Update, Error, Email, Success, Failed, Locked, Unlocked, "Logged out", Undelete, "Maintain Schedule", "Permanent Delete", "Update for Internal Only"
        #[arg(long, value_parser = clap::value_parser!(AuditAction))]
        audit_action: Vec<AuditAction>,

        /// Action types to filter. Valid values: "Login Account", Admin, Auth, Login
        #[arg(long, value_parser = clap::value_parser!(ActionType))]
        action_type: Vec<ActionType>,

        /// Treat input datetimes as UTC (default: local timezone)
        #[arg(long)]
        utc: bool,

        /// Disable automatic detection of last log file timestamp
        /// By default, the tool will check for the last log file and use its timestamp as the start time
        #[arg(long)]
        no_file_timestamp: bool,

        /// Disable log deduplication
        /// By default, logs are deduplicated against recent log files to prevent duplicates
        #[arg(long)]
        no_dedup: bool,

        /// Backend refresh window (format: Nm, Nh)
        /// Only stop early on empty chunks within this window from now
        /// Examples: 60m, 90m, 2h, 3h
        /// Range: 30 minutes - 4 hours
        #[arg(long, default_value = "2h", value_parser = validate_backend_window)]
        backend_window: String,
    },

    /// Run continuous audit log retrieval (service mode)
    Service {
        /// Start offset from now. Format: Nm (minutes), Nh (hours), or Nd (days)
        /// Examples: 30m, 2h, 7d
        /// Determines how far back to start querying from
        #[arg(long, default_value = "15m", value_parser = validate_time_offset)]
        start_offset: String,

        /// Interval/window size for queries. Format: Nm (minutes), Nh (hours)
        /// Examples: 15m, 30m, 1h
        /// Range: 5-60 minutes
        /// Service will query in chunks of this interval size and run every 'interval' duration
        #[arg(short, long, default_value = "15m", value_parser = validate_interval)]
        interval: String,

        /// Output directory for audit log files
        #[arg(short, long, default_value = "./audit_logs", value_parser = validate_directory)]
        output_dir: String,

        /// Keep only the last N files (must be > 0)
        #[arg(long, value_parser = validate_count)]
        cleanup_count: Option<usize>,

        /// Delete files older than N hours (must be > 0)
        #[arg(long, value_parser = validate_hours)]
        cleanup_hours: Option<u64>,

        /// Audit actions to filter. Valid values: Create, Delete, Update, Error, Email, Success, Failed, Locked, Unlocked, "Logged out", Undelete, "Maintain Schedule", "Permanent Delete", "Update for Internal Only"
        #[arg(long, value_parser = clap::value_parser!(AuditAction))]
        audit_action: Vec<AuditAction>,

        /// Action types to filter. Valid values: "Login Account", Admin, Auth, Login
        #[arg(long, value_parser = clap::value_parser!(ActionType))]
        action_type: Vec<ActionType>,

        /// Treat input datetimes as UTC (default: local timezone)
        #[arg(long)]
        utc: bool,

        /// Disable automatic detection of last log file timestamp
        /// By default, the tool will check for the last log file and use its timestamp as the start time
        #[arg(long)]
        no_file_timestamp: bool,

        /// Disable log deduplication
        /// By default, logs are deduplicated against recent log files to prevent duplicates
        #[arg(long)]
        no_dedup: bool,

        /// Backend refresh window (format: Nm, Nh)
        /// Only stop early on empty chunks within this window from now
        /// Examples: 60m, 90m, 2h, 3h
        /// Range: 30 minutes - 4 hours
        #[arg(long, default_value = "2h", value_parser = validate_backend_window)]
        backend_window: String,
    },

    /// Display help for environment variables
    HelpEnv,
}

/// Validate cleanup count (> 0)
fn validate_count(s: &str) -> Result<usize, String> {
    let value: usize = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid number", s))?;
    if value == 0 {
        return Err("Cleanup count must be greater than 0".to_string());
    }
    Ok(value)
}

/// Validate cleanup hours (> 0)
fn validate_hours(s: &str) -> Result<u64, String> {
    let value: u64 = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid number", s))?;
    if value == 0 {
        return Err("Cleanup hours must be greater than 0".to_string());
    }
    Ok(value)
}

/// Validate datetime format (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
fn validate_datetime(s: &str) -> Result<String, String> {
    use chrono::{NaiveDate, NaiveDateTime};

    let s_trimmed = s.trim();

    if s_trimmed.is_empty() {
        return Err("Datetime cannot be empty".to_string());
    }

    // Try to parse as YYYY-MM-DD HH:MM:SS
    if NaiveDateTime::parse_from_str(s_trimmed, "%Y-%m-%d %H:%M:%S").is_ok() {
        return Ok(s.to_string());
    }

    // Try to parse as YYYY-MM-DD
    if NaiveDate::parse_from_str(s_trimmed, "%Y-%m-%d").is_ok() {
        return Ok(s.to_string());
    }

    Err(format!(
        "Invalid datetime format: '{}'. Expected: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS",
        s
    ))
}

/// Validate time offset format (Nm, Nh, Nd, or just N for minutes)
fn validate_time_offset(s: &str) -> Result<String, String> {
    let s_trimmed = s.trim();

    // Check if it ends with a valid unit or is just a number
    if s_trimmed.is_empty() {
        return Err("Time offset cannot be empty".to_string());
    }

    let num_str = if s_trimmed.ends_with('m') {
        s_trimmed.trim_end_matches('m')
    } else if s_trimmed.ends_with('h') {
        s_trimmed.trim_end_matches('h')
    } else if s_trimmed.ends_with('d') {
        s_trimmed.trim_end_matches('d')
    } else {
        // No unit, assume minutes - just validate it's a number
        s_trimmed
    };

    // Validate the numeric part
    let value: i64 = num_str.parse().map_err(|_| {
        format!(
            "Invalid time offset: '{}'. Expected a positive number optionally followed by 'm', 'h', or 'd'",
            s
        )
    })?;

    if value <= 0 {
        return Err("Time offset must be a positive value".to_string());
    }

    Ok(s.to_string())
}

/// Validate interval is within allowed range (5-60 minutes)
fn validate_interval(s: &str) -> Result<String, String> {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() {
        return Err("Interval cannot be empty".to_string());
    }

    // Parse the value and unit
    let (num_str, unit) = if s_trimmed.ends_with('m') {
        (s_trimmed.trim_end_matches('m'), "m")
    } else if s_trimmed.ends_with('h') {
        (s_trimmed.trim_end_matches('h'), "h")
    } else if s_trimmed.ends_with('d') {
        (s_trimmed.trim_end_matches('d'), "d")
    } else {
        // No unit, assume minutes
        (s_trimmed, "m")
    };

    // Parse the numeric value
    let value: i64 = num_str.parse().map_err(|_| {
        format!(
            "Invalid interval: '{}'. Expected a positive number optionally followed by 'm', 'h', or 'd'",
            s
        )
    })?;

    if value <= 0 {
        return Err("Interval must be a positive value".to_string());
    }

    // Convert to minutes for range check
    let minutes = match unit {
        "m" => value,
        "h" => value * 60,
        "d" => value * 60 * 24,
        _ => value, // Default to minutes
    };

    // Validate range: 5-60 minutes
    if minutes < 5 {
        return Err(format!(
            "Interval must be at least 5 minutes (got {} minutes)",
            minutes
        ));
    }

    if minutes > 60 {
        return Err(format!(
            "Interval must not exceed 60 minutes (got {} minutes)",
            minutes
        ));
    }

    Ok(s.to_string())
}

/// Validate backend refresh window (30 minutes to 4 hours)
fn validate_backend_window(s: &str) -> Result<String, String> {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() {
        return Err("Backend window cannot be empty".to_string());
    }

    // Parse the value and unit
    let (num_str, unit) = if s_trimmed.ends_with('m') {
        (s_trimmed.trim_end_matches('m'), "m")
    } else if s_trimmed.ends_with('h') {
        (s_trimmed.trim_end_matches('h'), "h")
    } else {
        return Err("Backend window must end with 'm' or 'h'".to_string());
    };

    // Parse the numeric value
    let value: i64 = num_str
        .parse()
        .map_err(|_| format!("Invalid backend window: '{}'. Expected format: Nm or Nh", s))?;

    if value <= 0 {
        return Err("Backend window must be positive".to_string());
    }

    // Convert to minutes for range check
    let minutes = match unit {
        "m" => value,
        "h" => value * 60,
        _ => value,
    };

    // Range: 30 minutes to 4 hours
    if minutes < 30 {
        return Err(format!(
            "Backend window must be at least 30 minutes (got {} minutes)",
            minutes
        ));
    }

    if minutes > 240 {
        return Err(format!(
            "Backend window must not exceed 4 hours (got {} minutes)",
            minutes
        ));
    }

    Ok(s.to_string())
}

/// Validate output directory is accessible or can be created
fn validate_directory(s: &str) -> Result<String, String> {
    use std::fs;
    use std::path::Path;

    let path = Path::new(s);

    // Check if directory already exists
    if path.exists() {
        // Verify it's actually a directory
        if !path.is_dir() {
            return Err(format!("Path '{}' exists but is not a directory", s));
        }

        // Check if we can read the directory
        if fs::read_dir(path).is_err() {
            return Err(format!(
                "Directory '{}' exists but is not readable (permission denied)",
                s
            ));
        }

        // Check if we can write to the directory by checking metadata
        let metadata =
            fs::metadata(path).map_err(|e| format!("Cannot access directory '{}': {}", s, e))?;

        if metadata.permissions().readonly() {
            return Err(format!(
                "Directory '{}' is read-only (permission denied)",
                s
            ));
        }

        // On Unix systems, do an additional write permission check
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            // Check if owner has write permission (bit 7)
            if (mode & 0o200) == 0 {
                return Err(format!(
                    "Directory '{}' is not writable (permission denied)",
                    s
                ));
            }
        }

        Ok(s.to_string())
    } else {
        // Directory doesn't exist - check if we can create it
        // Find the first existing parent directory
        let mut parent = path;
        let mut first_existing_parent = None;

        while let Some(p) = parent.parent() {
            if p.exists() {
                first_existing_parent = Some(p);
                break;
            }
            parent = p;
        }

        if let Some(existing_parent) = first_existing_parent {
            // Check if parent directory is writable
            let metadata = fs::metadata(existing_parent).map_err(|e| {
                format!(
                    "Cannot access parent directory '{}': {}",
                    existing_parent.display(),
                    e
                )
            })?;

            if !existing_parent.is_dir() {
                return Err(format!(
                    "Parent path '{}' is not a directory",
                    existing_parent.display()
                ));
            }

            if metadata.permissions().readonly() {
                return Err(format!(
                    "Cannot create directory '{}': parent directory '{}' is read-only (permission denied)",
                    s,
                    existing_parent.display()
                ));
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                // Check if owner has write permission
                if (mode & 0o200) == 0 {
                    return Err(format!(
                        "Cannot create directory '{}': parent directory '{}' is not writable (permission denied)",
                        s,
                        existing_parent.display()
                    ));
                }
            }

            Ok(s.to_string())
        } else {
            // No parent exists at all
            Err(format!(
                "Cannot create directory '{}': no parent directory exists",
                s
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_directory_existing_writable() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_str().unwrap();

        let result = validate_directory(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn test_validate_directory_new_in_writable_parent() {
        let temp_dir = TempDir::new().unwrap();
        let new_dir = temp_dir.path().join("new_subdir");
        let path = new_dir.to_str().unwrap();

        let result = validate_directory(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn test_validate_directory_nested_new_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("level1").join("level2").join("level3");
        let path = nested_dir.to_str().unwrap();

        let result = validate_directory(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn test_validate_directory_path_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        fs::write(&file_path, "test content").unwrap();

        let result = validate_directory(file_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("exists but is not a directory")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_directory_readonly() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let readonly_dir = temp_dir.path().join("readonly");
        fs::create_dir(&readonly_dir).unwrap();

        // Make directory read-only
        let mut perms = fs::metadata(&readonly_dir).unwrap().permissions();
        perms.set_mode(0o444); // r--r--r--
        fs::set_permissions(&readonly_dir, perms).unwrap();

        let result = validate_directory(readonly_dir.to_str().unwrap());

        // Restore permissions before cleanup
        let mut perms = fs::metadata(&readonly_dir).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&readonly_dir, perms).unwrap();

        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("not writable") || error_msg.contains("read-only"));
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_directory_readonly_parent() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let readonly_parent = temp_dir.path().join("readonly_parent");
        fs::create_dir(&readonly_parent).unwrap();

        // Make parent directory read-only
        let mut perms = fs::metadata(&readonly_parent).unwrap().permissions();
        perms.set_mode(0o444); // r--r--r--
        fs::set_permissions(&readonly_parent, perms).unwrap();

        let new_dir = readonly_parent.join("child");
        let result = validate_directory(new_dir.to_str().unwrap());

        // Restore permissions before cleanup
        let mut perms = fs::metadata(&readonly_parent).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&readonly_parent, perms).unwrap();

        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("not writable") || error_msg.contains("read-only"));
    }

    #[test]
    fn test_validate_directory_parent_is_file() {
        // Try to create a directory where parent is a file, not a directory
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("somefile.txt");
        fs::write(&file_path, "content").unwrap();

        // Try to create a directory under this file
        let invalid_dir = file_path.join("subdir");
        let result = validate_directory(invalid_dir.to_str().unwrap());

        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("not a directory"));
    }

    #[test]
    fn test_validate_datetime_valid_date() {
        let result = validate_datetime("2025-01-15");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2025-01-15");
    }

    #[test]
    fn test_validate_datetime_valid_datetime() {
        let result = validate_datetime("2025-01-15 14:30:00");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2025-01-15 14:30:00");
    }

    #[test]
    fn test_validate_datetime_invalid() {
        let result = validate_datetime("invalid-date");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid datetime format"));
    }

    #[test]
    fn test_validate_time_offset_minutes() {
        let result = validate_time_offset("30m");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "30m");
    }

    #[test]
    fn test_validate_time_offset_hours() {
        let result = validate_time_offset("2h");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2h");
    }

    #[test]
    fn test_validate_time_offset_days() {
        let result = validate_time_offset("7d");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "7d");
    }

    #[test]
    fn test_validate_time_offset_plain_number() {
        let result = validate_time_offset("45");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "45");
    }

    #[test]
    fn test_validate_time_offset_invalid() {
        let result = validate_time_offset("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid time offset"));
    }

    #[test]
    fn test_validate_time_offset_negative() {
        let result = validate_time_offset("-5m");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("positive value"));
    }
}
