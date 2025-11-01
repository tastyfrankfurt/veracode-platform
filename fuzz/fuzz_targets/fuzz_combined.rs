#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use veraaudit::datetime::{
    add_interval_to_datetime, parse_time_offset, subtract_minutes_from_datetime,
    validate_date_range, validate_datetime_format,
};
use veraaudit::validation::{ActionType, AuditAction, Region};

fuzz_target!(|data: &[u8]| {
    if let Ok(input_str) = std::str::from_utf8(data) {
        // Test all FromStr implementations
        let _ = AuditAction::from_str(input_str);
        let _ = ActionType::from_str(input_str);
        let region_result = Region::from_str(input_str);

        // Use parsed region (or default) for datetime tests
        let region = region_result.unwrap_or(Region::Commercial);

        // Test datetime parsing and validation
        let _ = validate_datetime_format(input_str, "fuzz", true, &region);
        let _ = parse_time_offset(input_str);

        // If input is long enough, split and test combinations
        if data.len() >= 20 {
            // Split into thirds for different test scenarios
            let third = data.len() / 3;
            let two_thirds = (data.len() * 2) / 3;

            if let (Ok(part1), Ok(part2), Ok(part3)) = (
                std::str::from_utf8(&data[..third]),
                std::str::from_utf8(&data[third..two_thirds]),
                std::str::from_utf8(&data[two_thirds..]),
            ) {
                // Test date range validation
                let _ = validate_date_range(part1, part2, true, &region);

                // Test adding intervals
                let _ = add_interval_to_datetime(part1, part3);
                let _ = add_interval_to_datetime(part2, part3);

                // Test subtracting minutes (use length as minutes value)
                let minutes = (part3.len() % 100000) as i64;
                let _ = subtract_minutes_from_datetime(part1, minutes);
            }
        }
    }
});
