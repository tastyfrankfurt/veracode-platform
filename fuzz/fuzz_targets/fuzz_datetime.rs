#![no_main]

use libfuzzer_sys::fuzz_target;
use veraaudit::datetime::{
    add_interval_to_datetime, parse_time_offset, subtract_minutes_from_datetime,
};
use veraaudit::validation::Region;

fuzz_target!(|data: &[u8]| {
    // Try to convert fuzzer input to a string
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz parse_time_offset - tests parsing of "30m", "2h", "1d" format
        let _ = parse_time_offset(s);

        // Fuzz datetime parsing with all regions
        for region in &[Region::Commercial, Region::European, Region::Federal] {
            let _ = veraaudit::datetime::validate_datetime_format(s, "fuzz", true, region);
        }

        // Fuzz try_parse_datetime
        let _ = veraaudit::datetime::try_parse_datetime(s);

        // If we can split the input into two parts, test date range validation
        if let Some(mid) = data.len().checked_div(2) {
            if mid > 0 && mid < data.len() {
                if let (Ok(start), Ok(end)) = (
                    std::str::from_utf8(&data[..mid]),
                    std::str::from_utf8(&data[mid..]),
                ) {
                    let _ = veraaudit::datetime::validate_date_range(
                        start,
                        end,
                        true,
                        &Region::Commercial,
                    );
                }
            }
        }

        // Fuzz add_interval_to_datetime - split input for datetime and interval
        if data.len() >= 4 {
            let split_point = data.len() / 2;
            if let (Ok(datetime_str), Ok(interval_str)) = (
                std::str::from_utf8(&data[..split_point]),
                std::str::from_utf8(&data[split_point..]),
            ) {
                let _ = add_interval_to_datetime(datetime_str, interval_str);
            }
        }

        // Fuzz subtract_minutes_from_datetime
        // Use length of remaining bytes as minutes value
        if !s.is_empty() {
            let minutes = (data.len() % 10000) as i64;
            let _ = subtract_minutes_from_datetime(s, minutes);
        }
    }
});
