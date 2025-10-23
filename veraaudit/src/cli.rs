//! CLI argument parsing for veraaudit
use crate::validation::{ActionType, AuditAction, Region};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "veraaudit",
    version,
    about = "Veracode audit log retrieval tool",
    long_about = "CLI tool for retrieving and archiving Veracode audit logs using the Reporting REST API"
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
        #[arg(short, long, conflicts_with = "start_offset")]
        start: Option<String>,

        /// Start offset from now. Format: Nm (minutes), Nh (hours), or Nd (days)
        /// Examples: 30m, 2h, 7d
        /// Cannot be used with --start
        #[arg(long, conflicts_with = "start")]
        start_offset: Option<String>,

        /// End datetime (UTC). Format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS
        /// Defaults to current time if not specified
        #[arg(short, long)]
        end: Option<String>,

        /// Output directory for audit log files
        #[arg(short, long, default_value = "./audit_logs")]
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
    },

    /// Run continuous audit log retrieval (service mode)
    Service {
        /// Retrieval interval in minutes (must be between 5-60)
        #[arg(short, long, default_value = "15", value_parser = validate_interval)]
        interval_minutes: u64,

        /// Output directory for audit log files
        #[arg(short, long, default_value = "./audit_logs")]
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
    },
}

/// Validate interval minutes (5-60)
fn validate_interval(s: &str) -> Result<u64, String> {
    let value: u64 = s
        .parse()
        .map_err(|_| format!("'{}' is not a valid number", s))?;
    if !(5..=60).contains(&value) {
        return Err(format!(
            "Interval must be between 5 and 60 minutes, got: {}",
            value
        ));
    }
    Ok(value)
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
