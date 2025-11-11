# Fuzzing Guide for Veracode Workspace

This directory contains comprehensive fuzzing targets for all Veracode workspace applications (verascan, veracmek, veraaudit). The fuzzing infrastructure tests input validation, parsing, and deserialization across 65+ identified security-critical functions.

## Prerequisites

- Rust nightly toolchain: `rustup install nightly`
- cargo-fuzz: `cargo install cargo-fuzz`

## Available Fuzz Targets

### Category 1: CLI Input Validators

#### `fuzz_cli_validators` (Veraaudit)
Tests CLI-specific validation functions from clap value parsers:
- `validate_datetime` - Datetime format validation (YYYY-MM-DD, YYYY-MM-DD HH:MM:SS)
- `validate_time_offset` - Time offset parsing with validation
- `validate_interval` - Range validation: 5-60 minutes
- `validate_backend_window` - Range validation: 30 minutes to 4 hours
- `validate_count` - Cleanup count validation (> 0)
- `validate_hours` - Cleanup hours validation (> 0)

**Note**: `validate_directory` is excluded as it performs filesystem I/O.

#### `fuzz_verascan_validators` (Verascan) **NEW**
Tests 19 verascan CLI validators:
- `validate_severity_level` - Severity validation (informational, very-low, low, medium, high, very-high)
- `validate_export_format` - Export format (json, csv, gitlab, all)
- `validate_region` - Region validation (commercial, european, federal)
- `validate_gitlab_schema_version` - GitLab schema version (15.2.1, 15.2.2, 15.2.3)
- `validate_findings_limit` - Findings limit (0 or 1-100)
- `validate_threads` - Thread count (2-10)
- `validate_name_field` - Name validation (max 70 chars, alphanumeric + -_  /)
- `validate_sandbox_name` - Sandbox name with '/' replacement
- `validate_project_url` - **URL validation (https:// required)** 🔴 High Priority
- `validate_policy_name` - Policy name (max 100 chars)
- `validate_development_stage` - Development stage validation
- `validate_business_criticality` - Business criticality levels
- `validate_delete_incomplete_scan` - Delete policy (0, 1, or 2)
- `validate_build_version` - Build version string
- `validate_cmek_alias` - **AWS KMS alias (8-256 chars)** 🔴 High Priority
- `validate_fail_on_severity` - CSV severity list parsing
- `validate_fail_on_cwe` - CSV CWE ID parsing (numeric with optional CWE- prefix)
- `validate_modules_list` - CSV module name parsing
- `validate_api_credential` - **API credential validation** 🔴 High Priority
- `validate_api_credential_ascii` - ASCII-only credential validation

#### `fuzz_datetime` (Veraaudit)
Tests datetime parsing and manipulation:
- `parse_time_offset()` - Time offset strings ("30m", "2h", "1d")
- `validate_datetime_format()` - Datetime formats with timezone support
- `try_parse_datetime()` - Multi-format datetime parsing
- `validate_date_range()` - Date range validation (6-month limit)
- `add_interval_to_datetime()` - Interval addition
- `subtract_minutes_from_datetime()` - Minute subtraction

#### `fuzz_validation` (Veraaudit)
Tests enum parsing (FromStr implementations):
- `AuditAction::from_str()` - Audit actions (Create, Delete, Update, etc.)
- `ActionType::from_str()` - Action types (Admin, Login Account, etc.)
- `Region::from_str()` - Regions (commercial, european, federal)

### Category 2: API Response Deserializers

#### `fuzz_api_deserializers` **NEW**
Tests JSON/XML API response parsing (15+ deserializers):
- `FindingsResponse` - Pipeline scan findings (veracode-api/pipeline.rs)
- `Finding` - Individual security findings with nested structures
- `ScanStatus` - Scan status enum (SUCCESS, FAILURE, PENDING)
- `RestFindingsResponse` - HAL format REST API responses
- `RestFinding` - REST API finding details
- `FindingDetails` - Detailed finding information
- `Application` - Application profile deserialization
- `ApplicationsResponse` - Paginated applications (HAL format)
- `Profile` - Application profile with custom business criticality
- Deep nesting detection (DoS prevention)
- Binary JSON attack testing

### Category 3: HTML/XML Parsers

#### `fuzz_html_parser` **NEW** 🔴 High Priority
Tests HTML tag stripping (veracode-api/pipeline.rs:274):
- `strip_html_tags` - Character-by-character HTML parser
- Nested tag handling
- Unclosed tag edge cases
- Malformed tag handling (`<>`, `<<>>`)
- Script tag injection testing
- Attribute injection detection

**Security Note**: This fuzzer includes tests showing that script **content** is not removed (only tags), which could be a security issue.

### Category 4: Environment/Config Parsers

#### `fuzz_vault_parsers` **NEW** 🔴 High Priority
Tests Vault credential parsing:
- `parse_secret_path` - Secret path parsing (format: `secret/path@kvv2`)
- `validate_secret_data` - Secret size validation (1MB limit, 100 key limit)
- Vault URL parsing and HTTPS validation
- JSON secret deserialization
- Namespace parsing and validation

### Category 5: File Parsers

#### `fuzz_output_parsers` **NEW**
Tests log file parsing (veraaudit/output.rs):
- `extract_last_timestamp` - Timestamp extraction from JSON arrays
- `format_timestamp_for_filename` - Filename-safe timestamp formatting
- `parse_timestamp_from_filename` - Reverse timestamp parsing
- `compute_log_entry_hash` - xxHash computation for deduplication
- Filename pattern matching (`audit_logs_YYYY-MM-DD_HH-MM-SS-mmm.json`)

### Legacy/Combined Targets

#### `fuzz_combined`
Combines datetime + validation functions to test parser interactions.

## Running the Fuzzers

### List available targets
```bash
cd fuzz
cargo +nightly fuzz list
```

### Run a specific fuzzer
```bash
# Run for 60 seconds
cargo +nightly fuzz run fuzz_datetime -- -max_total_time=60

# Run with specific number of iterations
cargo +nightly fuzz run fuzz_validation -- -runs=1000000

# Run with multiple parallel jobs
cargo +nightly fuzz run fuzz_combined -- -jobs=4 -max_total_time=300
```

### Run all fuzzers sequentially
```bash
# Quick test (1 minute each)
for target in fuzz_datetime fuzz_validation fuzz_verascan_validators \
              fuzz_api_deserializers fuzz_html_parser fuzz_vault_parsers \
              fuzz_output_parsers; do
    echo "Running $target..."
    cargo +nightly fuzz run $target -- -max_total_time=60
done
```

## Manual Fuzzing Examples

### Quick Smoke Test (2 minutes each)

```bash
# Test high-priority targets quickly
cargo +nightly fuzz run fuzz_verascan_validators -- -max_total_time=120
cargo +nightly fuzz run fuzz_html_parser -- -max_total_time=120
cargo +nightly fuzz run fuzz_vault_parsers -- -max_total_time=120
```

### Standard Test Session (5-10 minutes each)

```bash
# Test all new targets
cargo +nightly fuzz run fuzz_verascan_validators -- -max_total_time=600 -print_final_stats=1
cargo +nightly fuzz run fuzz_api_deserializers -- -max_total_time=600 -print_final_stats=1
cargo +nightly fuzz run fuzz_html_parser -- -max_total_time=600 -print_final_stats=1
cargo +nightly fuzz run fuzz_vault_parsers -- -max_total_time=600 -print_final_stats=1
cargo +nightly fuzz run fuzz_output_parsers -- -max_total_time=600 -print_final_stats=1
```

### Comprehensive Security Testing (30-60 minutes each)

```bash
# Run security-focused fuzzing with multiple workers
cargo +nightly fuzz run fuzz_verascan_validators -- \
  -max_total_time=3600 \
  -workers=4 \
  -jobs=4 \
  -print_coverage=1 \
  -print_final_stats=1

cargo +nightly fuzz run fuzz_html_parser -- \
  -max_total_time=1800 \
  -detect_leaks=1 \
  -print_final_stats=1
```

### Priority-Based Fuzzing Routine

Based on security risk analysis, run targets in this order:

```bash
#!/bin/bash
# priority_fuzz.sh

echo "=== HIGH PRIORITY TARGETS ==="

echo "1. URL/CMEK validators (SSRF, injection risk)"
cargo +nightly fuzz run fuzz_verascan_validators -- -max_total_time=1800

echo "2. HTML parser (XSS risk)"
cargo +nightly fuzz run fuzz_html_parser -- -max_total_time=1800

echo "3. Vault parsers (credential bypass risk)"
cargo +nightly fuzz run fuzz_vault_parsers -- -max_total_time=1800

echo "=== MEDIUM PRIORITY TARGETS ==="

echo "4. Datetime parsers (timezone/DST bugs)"
cargo +nightly fuzz run fuzz_datetime -- -max_total_time=900

echo "5. API deserializers (DoS via nested JSON)"
cargo +nightly fuzz run fuzz_api_deserializers -- -max_total_time=900

echo "=== LOW PRIORITY TARGETS ==="

echo "6. Output parsers"
cargo +nightly fuzz run fuzz_output_parsers -- -max_total_time=600

echo "7. Combined validators"
cargo +nightly fuzz run fuzz_combined -- -max_total_time=600

echo "=== FUZZING COMPLETE ==="
echo "Check for crashes in fuzz/artifacts/"
find fuzz/artifacts -type f
```

## Advanced Usage

### Code Coverage Analysis
```bash
cargo +nightly fuzz coverage fuzz_datetime
```

### Minimize Corpus
```bash
cargo +nightly fuzz cmin fuzz_datetime
```

### Run with AddressSanitizer
```bash
cargo +nightly fuzz run fuzz_datetime --sanitizer=address
```

### Additional libFuzzer Options
```bash
# Custom timeout per test case (in seconds)
cargo +nightly fuzz run fuzz_datetime -- -timeout=1

# Maximum input length
cargo +nightly fuzz run fuzz_datetime -- -max_len=256

# Generate only ASCII inputs
cargo +nightly fuzz run fuzz_datetime -- -only_ascii=1

# Print stats periodically
cargo +nightly fuzz run fuzz_datetime -- -print_final_stats=1
```

## Corpus and Artifacts

- **Corpus**: Interesting test cases are saved in `corpus/<target_name>/`
- **Artifacts**: Crash-inducing inputs are saved in `artifacts/<target_name>/`

If a fuzzer finds a crash, you can reproduce it with:
```bash
cargo +nightly fuzz run fuzz_datetime artifacts/fuzz_datetime/crash-<hash>
```

## Integration with CI/CD

You can integrate fuzzing into your CI pipeline:

```bash
# Run each fuzzer for a short time in CI
cargo +nightly fuzz run fuzz_datetime -- -max_total_time=30 -runs=100000
cargo +nightly fuzz run fuzz_validation -- -max_total_time=30 -runs=100000
cargo +nightly fuzz run fuzz_combined -- -max_total_time=30 -runs=100000
cargo +nightly fuzz run fuzz_cli_validators -- -max_total_time=30 -runs=100000
```

## Target Summary

### Complete Target List

| Target | Category | Functions | Priority | Status |
|--------|----------|-----------|----------|--------|
| `fuzz_verascan_validators` | CLI Validators | 19 validators | 🔴 High | ✅ Ready |
| `fuzz_html_parser` | HTML Parsing | strip_html_tags | 🔴 High | ✅ Ready |
| `fuzz_vault_parsers` | Credential Parsing | 5+ functions | 🔴 High | ✅ Ready |
| `fuzz_datetime` | Datetime Parsing | 6 functions | 🟡 Medium | ✅ Tested |
| `fuzz_api_deserializers` | JSON Deserializers | 15+ deserializers | 🟡 Medium | ✅ Ready |
| `fuzz_cli_validators` | CLI Validators | 6 validators | 🟡 Medium | ✅ Tested |
| `fuzz_output_parsers` | File Parsing | 5 functions | 🟢 Low | ✅ Ready |
| `fuzz_validation` | Enum Parsing | 3 FromStr impls | 🟢 Low | ✅ Tested |
| `fuzz_combined` | Combined | datetime + validation | 🟢 Low | ✅ Tested |

### Previous Test Results (Veraaudit Targets)

Baseline fuzzing results from veraaudit-only targets:

| Fuzzer | Initial Coverage | Extended Run Coverage | Test Cases | Exec/sec |
|--------|-----------------|----------------------|------------|----------|
| **fuzz_datetime** | 242 blocks | - | 37 | ~8,900 |
| **fuzz_validation** | 69 blocks | - | 8 | ~9,200 |
| **fuzz_combined** | 309 blocks | - | 45 | ~8,700 |
| **fuzz_cli_validators** | 189 blocks | **414 blocks** | **185** | **~8,917** |

**Extended Run (30 seconds)**: `fuzz_cli_validators` showed coverage growth from 189 → 414 blocks with 267,522 executions and **no crashes** ✅

## Interpreting Fuzzing Results

For a detailed guide on how to read and understand fuzzing output, see **[INTERPRETING_RESULTS.md](./INTERPRETING_RESULTS.md)**.

Quick reference:
- **cov: X** = Code blocks covered (higher is better)
- **NEW** = Found new coverage (good!)
- **REDUCE** = Found smaller input with same coverage (optimizing)
- **NEW_FUNC** = Discovered a new function (excellent!)
- **No crashes** = Code is robust ✅

## Fuzzing Best Practices

### Recommended Test Schedule

- **Before commits**: Run high-priority targets for 2 minutes each
- **Before PRs**: Run all targets for 5-10 minutes each
- **Weekly**: Run comprehensive test (30-60 minutes per target)
- **Before releases**: Run overnight tests (8+ hours per target)

### Monitoring for Crashes

```bash
# Quick check for any crashes
find fuzz/artifacts -type f

# Detailed crash report
for dir in fuzz/artifacts/*/; do
    if [ "$(ls -A $dir 2>/dev/null)" ]; then
        echo "CRASHES in $(basename $dir):"
        ls -lah "$dir"
    fi
done
```

### Reproducing and Minimizing Crashes

```bash
# Reproduce a crash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>

# Minimize the crashing input
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>

# Analyze with debugger
rust-gdb --args target/x86_64-unknown-linux-gnu/release/<target> \
  fuzz/artifacts/<target>/crash-<hash>
```

## Further Reading

- [Fuzzing Improvements (IMPROVEMENTS.md)](./IMPROVEMENTS.md) - Detailed findings from fuzzing veraaudit
- [Interpreting Results Guide](./INTERPRETING_RESULTS.md) - Understanding fuzzer output
- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)

---

**Total Coverage: 65+ security-critical functions across 9 fuzz targets**
