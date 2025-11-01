# Fuzzing for veraaudit

This directory contains fuzz targets for testing the veraaudit library using cargo-fuzz and libFuzzer.

## Prerequisites

- Rust nightly toolchain: `rustup install nightly`
- cargo-fuzz: `cargo install cargo-fuzz`

## Available Fuzz Targets

### 1. `fuzz_datetime`
Tests datetime parsing and manipulation functions:
- `parse_time_offset()` - Parses time offset strings ("30m", "2h", "1d")
- `validate_datetime_format()` - Validates datetime formats (YYYY-MM-DD, YYYY-MM-DD HH:MM:SS)
- `try_parse_datetime()` - Attempts to parse datetime strings
- `validate_date_range()` - Validates date ranges (start/end, 6-month limit)
- `add_interval_to_datetime()` - Adds time intervals to datetimes
- `subtract_minutes_from_datetime()` - Subtracts minutes from datetimes

### 2. `fuzz_validation`
Tests input validation and parsing:
- `AuditAction::from_str()` - Parses audit action strings (Create, Delete, Update, etc.)
- `ActionType::from_str()` - Parses action type strings (Admin, Login Account, Auth, etc.)
- `Region::from_str()` - Parses region strings (commercial, european, federal)

### 3. `fuzz_combined`
Combines all validation and datetime functions to test interactions between different parsers.

### 4. `fuzz_cli_validators`
Tests CLI-specific validation functions from clap value parsers:
- `validate_datetime` - Datetime format validation (YYYY-MM-DD, YYYY-MM-DD HH:MM:SS)
- `validate_time_offset` - Time offset parsing with validation
- `validate_interval` - **Range validation: 5-60 minutes**
- `validate_backend_window` - **Range validation: 30 minutes to 4 hours**
- `validate_count` - Cleanup count validation (> 0)
- `validate_hours` - Cleanup hours validation (> 0)

**Note**: `validate_directory` is intentionally excluded from fuzzing as it performs filesystem I/O operations which are slow, have side effects, and are non-deterministic.

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
for target in fuzz_datetime fuzz_validation fuzz_combined fuzz_cli_validators; do
    echo "Running $target..."
    cargo +nightly fuzz run $target -- -max_total_time=60
done
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

## Results

All fuzzers have been tested and run successfully with **no crashes found**:

| Fuzzer | Initial Coverage | Extended Run Coverage | Test Cases | Exec/sec |
|--------|-----------------|----------------------|------------|----------|
| **fuzz_datetime** | 242 blocks | - | 37 | ~8,900 |
| **fuzz_validation** | 69 blocks | - | 8 | ~9,200 |
| **fuzz_combined** | 309 blocks | - | 45 | ~8,700 |
| **fuzz_cli_validators** | 189 blocks | **414 blocks** | **185** | **~8,917** |

### Extended Run Results (30 seconds)

The `fuzz_cli_validators` fuzzer was run for an extended 30-second session:
- **Coverage Growth**: 189 → 414 blocks (+225 blocks discovered!)
- **Executions**: 267,522 runs in 30 seconds
- **Corpus Growth**: 26 → 185 test cases
- **New Functions**: Discovered multiple previously unreached functions
- **Crashes**: 0 ✅

This demonstrates the fuzzer's ability to discover new code paths over time.

## Interpreting Fuzzing Results

For a detailed guide on how to read and understand fuzzing output, see **[INTERPRETING_RESULTS.md](./INTERPRETING_RESULTS.md)**.

Quick reference:
- **cov: X** = Code blocks covered (higher is better)
- **NEW** = Found new coverage (good!)
- **REDUCE** = Found smaller input with same coverage (optimizing)
- **NEW_FUNC** = Discovered a new function (excellent!)
- **No crashes** = Code is robust ✅

## Further Reading

- [Interpreting Results Guide](./INTERPRETING_RESULTS.md) - Comprehensive guide to understanding fuzzer output
- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
