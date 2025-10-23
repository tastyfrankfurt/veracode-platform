//! DateTime validation and handling for audit log retrieval
use crate::error::{AuditError, Result};
use chrono::{DateTime, Duration, Local, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};

/// Supported datetime formats for the Veracode API
const FORMAT_DATE: &str = "%Y-%m-%d";
const FORMAT_DATETIME_SECOND: &str = "%Y-%m-%d %H:%M:%S";

/// Maximum date range allowed by Veracode API (6 months)
const MAX_RANGE_DAYS: i64 = 180;

/// Convert a datetime string from local timezone to UTC
///
/// This function parses the datetime string in the system's local timezone
/// and converts it to UTC. It supports all three datetime formats.
///
/// # Arguments
///
/// * `datetime_str` - The datetime string in local timezone
///
/// # Returns
///
/// The datetime string converted to UTC in the same format
///
/// # Errors
///
/// Returns error if the format is invalid
///
/// # Examples
///
/// ```no_run
/// use veraaudit::datetime::convert_local_to_utc;
///
/// // System timezone is EST (UTC-5)
/// let utc_str = convert_local_to_utc("2025-01-15 10:00:00").unwrap();
/// // Returns: "2025-01-15 15:00:00" (on systems in EST timezone)
/// ```
///
/// Note: The actual output depends on your system's timezone.
/// This example assumes EST (UTC-5) timezone.
pub fn convert_local_to_utc(datetime_str: &str) -> Result<String> {
    // Determine which format was used
    let (naive_dt, format) =
        if let Ok(dt) = NaiveDateTime::parse_from_str(datetime_str, FORMAT_DATETIME_SECOND) {
            (dt, FORMAT_DATETIME_SECOND)
        } else if let Ok(date) = NaiveDate::parse_from_str(datetime_str, FORMAT_DATE) {
            (
                date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap()),
                FORMAT_DATE,
            )
        } else {
            return Err(AuditError::InvalidDateTimeFormat(format!(
                "Invalid datetime format: '{}'. Expected: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS",
                datetime_str
            )));
        };

    // Convert from local timezone to UTC
    let local_time: DateTime<Local> =
        Local
            .from_local_datetime(&naive_dt)
            .single()
            .ok_or_else(|| {
                AuditError::InvalidDateTimeFormat(format!(
                    "Ambiguous datetime (DST transition?): {}",
                    datetime_str
                ))
            })?;

    let utc_time = local_time.with_timezone(&Utc);

    // Format back using the same format as input
    match format {
        FORMAT_DATE => Ok(utc_time.format(FORMAT_DATE).to_string()),
        FORMAT_DATETIME_SECOND => Ok(utc_time.format(FORMAT_DATETIME_SECOND).to_string()),
        _ => unreachable!(),
    }
}

/// Validate a datetime string and ensure it matches one of the supported formats
///
/// Supported formats:
/// - YYYY-MM-DD (date only, time defaults to 00:00:00)
/// - YYYY-MM-DD HH:MM:SS (datetime with second precision)
///
/// # Arguments
///
/// * `datetime_str` - The datetime string to validate
/// * `field_name` - Name of the field (for error messages)
/// * `utc_mode` - If false, interpret as local timezone and convert to UTC; if true, treat as UTC
///
/// # Returns
///
/// The validated datetime string (converted to UTC if utc_mode is false)
///
/// # Errors
///
/// Returns error if the format is invalid or the datetime is in the future
pub fn validate_datetime_format(
    datetime_str: &str,
    field_name: &str,
    utc_mode: bool,
) -> Result<String> {
    // Convert to UTC if not in UTC mode
    let utc_datetime_str = if utc_mode {
        datetime_str.to_string()
    } else {
        convert_local_to_utc(datetime_str)?
    };

    // Try to parse in order of specificity (most specific first)
    let parsed_dt = try_parse_datetime(&utc_datetime_str)?;

    // Check if datetime is in the future
    if parsed_dt > Utc::now() {
        return Err(AuditError::DateRangeInvalid(format!(
            "{} cannot be in the future: {}",
            field_name,
            if utc_mode {
                datetime_str
            } else {
                &format!("{} (local) / {} (UTC)", datetime_str, utc_datetime_str)
            }
        )));
    }

    Ok(utc_datetime_str)
}

/// Try to parse a datetime string using all supported formats
fn try_parse_datetime(datetime_str: &str) -> Result<DateTime<Utc>> {
    // Try format: YYYY-MM-DD HH:MM:SS
    if let Ok(dt) = NaiveDateTime::parse_from_str(datetime_str, FORMAT_DATETIME_SECOND) {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }

    // Try format: YYYY-MM-DD (date only, time = 00:00:00)
    if let Ok(date) = NaiveDate::parse_from_str(datetime_str, FORMAT_DATE) {
        let dt = date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap());
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }

    Err(AuditError::InvalidDateTimeFormat(format!(
        "Invalid datetime format: '{}'. Expected: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS",
        datetime_str
    )))
}

/// Validate a date range (start and end datetimes)
///
/// Validates:
/// - Both datetimes have valid formats
/// - Start is before end
/// - Range doesn't exceed 6 months (Veracode API limit)
///
/// # Arguments
///
/// * `start` - Start datetime string
/// * `end` - End datetime string
/// * `utc_mode` - If false, interpret as local timezone and convert to UTC; if true, treat as UTC
///
/// # Returns
///
/// Tuple of validated (start, end) strings (converted to UTC if utc_mode is false)
///
/// # Errors
///
/// Returns error if validation fails
pub fn validate_date_range(start: &str, end: &str, utc_mode: bool) -> Result<(String, String)> {
    // Validate individual formats (this handles timezone conversion)
    let start_validated = validate_datetime_format(start, "Start datetime", utc_mode)?;
    let end_validated = validate_datetime_format(end, "End datetime", utc_mode)?;

    // Parse for range validation (both are now in UTC)
    let start_dt = try_parse_datetime(&start_validated)?;
    let end_dt = try_parse_datetime(&end_validated)?;

    // Check start < end
    if start_dt >= end_dt {
        return Err(AuditError::DateRangeInvalid(format!(
            "Start datetime must be before end datetime: start='{}', end='{}'",
            start, end
        )));
    }

    // Check 6-month maximum range
    let range_days = (end_dt - start_dt).num_days();
    if range_days > MAX_RANGE_DAYS {
        return Err(AuditError::DateRangeInvalid(format!(
            "Date range exceeds maximum of {} days (6 months): {} days between '{}' and '{}'",
            MAX_RANGE_DAYS, range_days, start, end
        )));
    }

    Ok((start_validated, end_validated))
}

/// Format current UTC time as YYYY-MM-DD HH:MM:SS
pub fn format_now_utc() -> String {
    Utc::now().format(FORMAT_DATETIME_SECOND).to_string()
}

/// Format UTC time minus specified minutes as YYYY-MM-DD HH:MM:SS
pub fn format_utc_minus_minutes(minutes: i64) -> String {
    let dt = Utc::now() - Duration::minutes(minutes);
    dt.format(FORMAT_DATETIME_SECOND).to_string()
}

/// Parse a time offset string and return the duration in minutes
///
/// Supported formats:
/// - `Nm` or `N` - N minutes
/// - `Nh` - N hours
/// - `Nd` - N days
///
/// # Arguments
///
/// * `offset_str` - The offset string to parse (e.g., "30m", "2h", "1d")
///
/// # Returns
///
/// The offset in minutes
///
/// # Errors
///
/// Returns error if the format is invalid or the value is not a positive number
///
/// # Examples
///
/// ```
/// use veraaudit::datetime::parse_time_offset;
///
/// assert_eq!(parse_time_offset("30m").unwrap(), 30);
/// assert_eq!(parse_time_offset("30").unwrap(), 30);
/// assert_eq!(parse_time_offset("2h").unwrap(), 120);
/// assert_eq!(parse_time_offset("1d").unwrap(), 1440);
/// ```
pub fn parse_time_offset(offset_str: &str) -> Result<i64> {
    let offset_str = offset_str.trim();

    // Check if it ends with a unit
    if offset_str.ends_with('m') {
        // Minutes
        let num_str = offset_str.trim_end_matches('m');
        let minutes: i64 = num_str.parse().map_err(|_| {
            AuditError::InvalidConfig(format!(
                "Invalid offset value: '{}'. Expected a positive number followed by 'm', 'h', or 'd'",
                offset_str
            ))
        })?;

        if minutes <= 0 {
            return Err(AuditError::InvalidConfig(
                "Offset must be a positive value".to_string(),
            ));
        }

        Ok(minutes)
    } else if offset_str.ends_with('h') {
        // Hours
        let num_str = offset_str.trim_end_matches('h');
        let hours: i64 = num_str.parse().map_err(|_| {
            AuditError::InvalidConfig(format!(
                "Invalid offset value: '{}'. Expected a positive number followed by 'm', 'h', or 'd'",
                offset_str
            ))
        })?;

        if hours <= 0 {
            return Err(AuditError::InvalidConfig(
                "Offset must be a positive value".to_string(),
            ));
        }

        Ok(hours * 60)
    } else if offset_str.ends_with('d') {
        // Days
        let num_str = offset_str.trim_end_matches('d');
        let days: i64 = num_str.parse().map_err(|_| {
            AuditError::InvalidConfig(format!(
                "Invalid offset value: '{}'. Expected a positive number followed by 'm', 'h', or 'd'",
                offset_str
            ))
        })?;

        if days <= 0 {
            return Err(AuditError::InvalidConfig(
                "Offset must be a positive value".to_string(),
            ));
        }

        Ok(days * 24 * 60)
    } else {
        // No unit specified, assume minutes
        let minutes: i64 = offset_str.parse().map_err(|_| {
            AuditError::InvalidConfig(format!(
                "Invalid offset value: '{}'. Expected a positive number optionally followed by 'm', 'h', or 'd'",
                offset_str
            ))
        })?;

        if minutes <= 0 {
            return Err(AuditError::InvalidConfig(
                "Offset must be a positive value".to_string(),
            ));
        }

        Ok(minutes)
    }
}

/// Format UTC time minus a parsed offset as YYYY-MM-DD HH:MM:SS
///
/// # Arguments
///
/// * `offset_str` - The offset string to parse (e.g., "30m", "2h", "1d")
///
/// # Returns
///
/// The datetime string representing now minus the offset
///
/// # Errors
///
/// Returns error if the offset string is invalid
pub fn format_utc_minus_offset(offset_str: &str) -> Result<String> {
    let minutes = parse_time_offset(offset_str)?;
    Ok(format_utc_minus_minutes(minutes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_datetime_format_date_only() {
        let result = validate_datetime_format("2025-01-15", "test", true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2025-01-15");
    }

    #[test]
    fn test_validate_datetime_format_with_seconds() {
        let result = validate_datetime_format("2025-01-15 14:30:45", "test", true);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "2025-01-15 14:30:45");
    }

    #[test]
    fn test_validate_datetime_format_invalid() {
        let result = validate_datetime_format("2025/01/15", "test", true);
        assert!(result.is_err());

        let result = validate_datetime_format("2025-01-15T14:30:45", "test", true);
        assert!(result.is_err());

        let result = validate_datetime_format("not-a-date", "test", true);
        assert!(result.is_err());

        // YYYY-MM-DD HH:MM format should be rejected (not supported by Veracode)
        let result = validate_datetime_format("2025-01-15 14:30", "test", true);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_datetime_format_future_date() {
        let future = format_utc_minus_minutes(-60); // 60 minutes in the future
        let result = validate_datetime_format(&future, "test", true);
        assert!(result.is_err());
        assert!(matches!(result, Err(AuditError::DateRangeInvalid(_))));
    }

    #[test]
    fn test_validate_date_range_valid() {
        let result = validate_date_range("2025-01-01", "2025-01-31", true);
        assert!(result.is_ok());
        let (start, end) = result.unwrap();
        assert_eq!(start, "2025-01-01");
        assert_eq!(end, "2025-01-31");
    }

    #[test]
    fn test_validate_date_range_with_times() {
        let result = validate_date_range("2025-01-01 10:00:00", "2025-01-01 11:30:00", true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_date_range_start_after_end() {
        let result = validate_date_range("2025-01-31", "2025-01-01", true);
        assert!(result.is_err());
        assert!(matches!(result, Err(AuditError::DateRangeInvalid(_))));
    }

    #[test]
    fn test_validate_date_range_exceeds_6_months() {
        let result = validate_date_range("2024-01-01", "2024-12-31", true);
        assert!(result.is_err());
        assert!(matches!(result, Err(AuditError::DateRangeInvalid(_))));
    }

    #[test]
    fn test_format_now_utc() {
        let now = format_now_utc();
        // Should match format YYYY-MM-DD HH:MM:SS
        assert!(validate_datetime_format(&now, "test", true).is_ok());
    }

    #[test]
    fn test_format_utc_minus_minutes() {
        let earlier = format_utc_minus_minutes(60);
        assert!(validate_datetime_format(&earlier, "test", true).is_ok());
    }

    #[test]
    fn test_parse_time_offset_minutes() {
        assert_eq!(parse_time_offset("30m").unwrap(), 30);
        assert_eq!(parse_time_offset("30").unwrap(), 30);
        assert_eq!(parse_time_offset("1").unwrap(), 1);
        assert_eq!(parse_time_offset("60m").unwrap(), 60);
    }

    #[test]
    fn test_parse_time_offset_hours() {
        assert_eq!(parse_time_offset("1h").unwrap(), 60);
        assert_eq!(parse_time_offset("2h").unwrap(), 120);
        assert_eq!(parse_time_offset("24h").unwrap(), 1440);
    }

    #[test]
    fn test_parse_time_offset_days() {
        assert_eq!(parse_time_offset("1d").unwrap(), 1440);
        assert_eq!(parse_time_offset("2d").unwrap(), 2880);
        assert_eq!(parse_time_offset("7d").unwrap(), 10080);
    }

    #[test]
    fn test_parse_time_offset_invalid() {
        // Zero is invalid
        assert!(parse_time_offset("0").is_err());
        assert!(parse_time_offset("0m").is_err());
        assert!(parse_time_offset("0h").is_err());
        assert!(parse_time_offset("0d").is_err());

        // Negative is invalid
        assert!(parse_time_offset("-1").is_err());
        assert!(parse_time_offset("-1m").is_err());

        // Invalid format
        assert!(parse_time_offset("abc").is_err());
        assert!(parse_time_offset("1x").is_err());
        assert!(parse_time_offset("m").is_err());
    }

    #[test]
    fn test_format_utc_minus_offset() {
        // Test minutes
        let result = format_utc_minus_offset("30m");
        assert!(result.is_ok());
        assert!(validate_datetime_format(&result.unwrap(), "test", true).is_ok());

        // Test hours
        let result = format_utc_minus_offset("2h");
        assert!(result.is_ok());
        assert!(validate_datetime_format(&result.unwrap(), "test", true).is_ok());

        // Test days
        let result = format_utc_minus_offset("1d");
        assert!(result.is_ok());
        assert!(validate_datetime_format(&result.unwrap(), "test", true).is_ok());

        // Test invalid
        let result = format_utc_minus_offset("invalid");
        assert!(result.is_err());
    }
}
