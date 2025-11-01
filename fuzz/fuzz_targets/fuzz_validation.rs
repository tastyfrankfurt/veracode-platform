#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str::FromStr;
use veraaudit::validation::{ActionType, AuditAction, Region};

fuzz_target!(|data: &[u8]| {
    // Try to convert fuzzer input to a string
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz AuditAction::from_str
        // This tests parsing of audit action strings like "Create", "Delete", "Update", etc.
        let _ = AuditAction::from_str(s);

        // Fuzz ActionType::from_str
        // This tests parsing of action type strings like "Admin", "Login Account", etc.
        let _ = ActionType::from_str(s);

        // Fuzz Region::from_str
        // This tests parsing of region strings like "commercial", "european", "federal"
        let _ = Region::from_str(s);
    }
});
