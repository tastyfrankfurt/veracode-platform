#![no_main]

use libfuzzer_sys::fuzz_target;

// We need to import the CLI validators, but they're private functions
// So we'll test them indirectly through the public CLI parsing
// Or we can test the same logic directly here

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Fuzz validate_datetime logic
        test_datetime_validation(input);

        // Fuzz validate_time_offset logic
        test_time_offset_validation(input);

        // Fuzz validate_interval logic (5-60 minutes range check)
        test_interval_validation(input);

        // Fuzz validate_backend_window logic (30m-4h range check)
        test_backend_window_validation(input);

        // Fuzz validate_count logic (> 0)
        test_count_validation(input);

        // Fuzz validate_hours logic (> 0)
        test_hours_validation(input);

        // Note: validate_directory is skipped as it performs filesystem I/O
        // which is not suitable for fuzzing (side effects, slow, non-deterministic)
    }
});

/// Test datetime validation logic (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
fn test_datetime_validation(s: &str) {
    use chrono::{NaiveDate, NaiveDateTime};

    let s_trimmed = s.trim();

    if s_trimmed.is_empty() {
        return;
    }

    // Try YYYY-MM-DD HH:MM:SS
    let _ = NaiveDateTime::parse_from_str(s_trimmed, "%Y-%m-%d %H:%M:%S");

    // Try YYYY-MM-DD
    let _ = NaiveDate::parse_from_str(s_trimmed, "%Y-%m-%d");
}

/// Test time offset validation logic
fn test_time_offset_validation(s: &str) {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() {
        return;
    }

    let num_str = if s_trimmed.ends_with('m') {
        s_trimmed.trim_end_matches('m')
    } else if s_trimmed.ends_with('h') {
        s_trimmed.trim_end_matches('h')
    } else if s_trimmed.ends_with('d') {
        s_trimmed.trim_end_matches('d')
    } else {
        s_trimmed
    };

    if let Ok(value) = num_str.parse::<i64>() {
        // Check if positive
        let _is_valid = value > 0;
    }
}

/// Test interval validation logic (5-60 minutes range)
fn test_interval_validation(s: &str) {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() {
        return;
    }

    // Parse the value and unit
    let (num_str, unit) = if s_trimmed.ends_with('m') {
        (s_trimmed.trim_end_matches('m'), "m")
    } else if s_trimmed.ends_with('h') {
        (s_trimmed.trim_end_matches('h'), "h")
    } else if s_trimmed.ends_with('d') {
        (s_trimmed.trim_end_matches('d'), "d")
    } else {
        (s_trimmed, "m")
    };

    if let Ok(value) = num_str.parse::<i64>() {
        if value > 0 {
            // Convert to minutes for range check
            let minutes = match unit {
                "m" => value,
                "h" => value.saturating_mul(60),
                "d" => value.saturating_mul(60).saturating_mul(24),
                _ => value,
            };

            // Check range: 5-60 minutes
            let _in_range = minutes >= 5 && minutes <= 60;
        }
    }
}

/// Test backend window validation logic (30 minutes to 4 hours)
fn test_backend_window_validation(s: &str) {
    let s_trimmed = s.trim();

    if s_trimmed.is_empty() {
        return;
    }

    // Parse the value and unit (must end with 'm' or 'h')
    let (num_str, unit) = if s_trimmed.ends_with('m') {
        (s_trimmed.trim_end_matches('m'), "m")
    } else if s_trimmed.ends_with('h') {
        (s_trimmed.trim_end_matches('h'), "h")
    } else {
        return;
    };

    if let Ok(value) = num_str.parse::<i64>() {
        if value > 0 {
            // Convert to minutes for range check
            let minutes = match unit {
                "m" => value,
                "h" => value.saturating_mul(60),
                _ => value,
            };

            // Check range: 30 minutes to 4 hours (240 minutes)
            let _in_range = minutes >= 30 && minutes <= 240;
        }
    }
}

/// Test count validation logic (> 0)
fn test_count_validation(s: &str) {
    if let Ok(value) = s.parse::<usize>() {
        let _is_valid = value > 0;
    }
}

/// Test hours validation logic (> 0)
fn test_hours_validation(s: &str) {
    if let Ok(value) = s.parse::<u64>() {
        let _is_valid = value > 0;
    }
}
