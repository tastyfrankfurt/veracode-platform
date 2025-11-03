# Fuzzing Run Commands - Quick Reference

## Automated Script (Recommended)

### Quick Test (2 minutes per target, high priority only)
```bash
cd /home/admin/code/veracode-workspace/fuzz
./run_all_fuzz_tests.sh 120 quick
```

### Standard Test (10 minutes per target, high + medium priority)
```bash
cd /home/admin/code/veracode-workspace/fuzz
./run_all_fuzz_tests.sh 600 standard
```

### Comprehensive Test (30 minutes per target, all targets)
```bash
cd /home/admin/code/veracode-workspace/fuzz
./run_all_fuzz_tests.sh 1800 comprehensive
```

### Show Help
```bash
cd /home/admin/code/veracode-workspace/fuzz
./run_all_fuzz_tests.sh --help
```

---

## Manual Commands

### One-Liner: Run All High Priority Targets (Quick)
```bash
cd /home/admin/code/veracode-workspace && for target in fuzz_verascan_validators fuzz_html_parser fuzz_vault_parsers; do echo "=== Fuzzing: $target ===" && cargo +nightly fuzz run "$target" -- -max_total_time=120 -print_final_stats=1; done
```

### One-Liner: Run All Targets (Standard)
```bash
cd /home/admin/code/veracode-workspace && for target in fuzz_verascan_validators fuzz_html_parser fuzz_vault_parsers fuzz_datetime fuzz_api_deserializers fuzz_cli_validators fuzz_output_parsers fuzz_validation fuzz_combined; do echo "=== Fuzzing: $target ===" && cargo +nightly fuzz run "$target" -- -max_total_time=600 -print_final_stats=1; done
```

### Individual Target Commands

#### High Priority (Run These First)
```bash
cd /home/admin/code/veracode-workspace

# URL/CMEK validators (SSRF, injection risk)
cargo +nightly fuzz run fuzz_verascan_validators -- -max_total_time=600 -print_final_stats=1

# HTML parser (XSS risk)
cargo +nightly fuzz run fuzz_html_parser -- -max_total_time=600 -print_final_stats=1

# Vault credential parsing (auth bypass risk)
cargo +nightly fuzz run fuzz_vault_parsers -- -max_total_time=600 -print_final_stats=1
```

#### Medium Priority
```bash
cd /home/admin/code/veracode-workspace

# Datetime parsers (timezone/DST bugs)
cargo +nightly fuzz run fuzz_datetime -- -max_total_time=600 -print_final_stats=1

# API deserializers (DoS via nested JSON)
cargo +nightly fuzz run fuzz_api_deserializers -- -max_total_time=600 -print_final_stats=1

# Veraaudit CLI validators
cargo +nightly fuzz run fuzz_cli_validators -- -max_total_time=600 -print_final_stats=1
```

#### Low Priority
```bash
cd /home/admin/code/veracode-workspace

# Output file parsing
cargo +nightly fuzz run fuzz_output_parsers -- -max_total_time=600 -print_final_stats=1

# Enum FromStr implementations
cargo +nightly fuzz run fuzz_validation -- -max_total_time=600 -print_final_stats=1

# Combined datetime + validation
cargo +nightly fuzz run fuzz_combined -- -max_total_time=600 -print_final_stats=1
```

---

## Check for Crashes

### Quick Check
```bash
cd /home/admin/code/veracode-workspace/fuzz
find artifacts -type f
```

### Detailed Check with Script
```bash
cd /home/admin/code/veracode-workspace/fuzz
for dir in artifacts/*/; do
    if [ "$(ls -A $dir 2>/dev/null)" ]; then
        echo "🚨 CRASHES in $(basename $dir):"
        ls -lah "$dir"
    fi
done
```

### One-Liner Crash Check
```bash
cd /home/admin/code/veracode-workspace/fuzz && find artifacts -type f -exec echo "Found crash: {}" \; || echo "No crashes found"
```

---

## Build and Verify

### List All Targets
```bash
cd /home/admin/code/veracode-workspace
cargo +nightly fuzz list
```

### Build All Targets (Check for Errors)
```bash
cd /home/admin/code/veracode-workspace
cargo +nightly fuzz build
```

### Build Specific Target
```bash
cd /home/admin/code/veracode-workspace
cargo +nightly fuzz build fuzz_verascan_validators
```

---

## Time Presets

| Duration | Seconds | Use Case |
|----------|---------|----------|
| Quick smoke test | 60 | Before commit (1 min) |
| Quick test | 120 | Rapid feedback (2 min) |
| Standard test | 600 | Normal testing (10 min) |
| Thorough test | 1800 | Pre-release (30 min) |
| Comprehensive | 3600 | Weekly run (1 hour) |
| Overnight | 28800 | Deep testing (8 hours) |

---

## Example Workflows

### Before Commit Workflow
```bash
cd /home/admin/code/veracode-workspace/fuzz
./run_all_fuzz_tests.sh 60 quick
```

### Before PR/Release Workflow
```bash
cd /home/admin/code/veracode-workspace/fuzz
./run_all_fuzz_tests.sh 600 standard
```

### Weekly Security Testing
```bash
cd /home/admin/code/veracode-workspace/fuzz
./run_all_fuzz_tests.sh 1800 comprehensive
```

### Overnight/Weekend Run
```bash
cd /home/admin/code/veracode-workspace/fuzz
nohup ./run_all_fuzz_tests.sh 28800 comprehensive > overnight_fuzz.log 2>&1 &
```

---

## Advanced Options

### Run with Multiple Workers (Parallel Execution)
```bash
cargo +nightly fuzz run fuzz_verascan_validators -- \
  -max_total_time=600 \
  -workers=4 \
  -jobs=4 \
  -print_final_stats=1
```

### Run with AddressSanitizer
```bash
RUSTFLAGS="-Zsanitizer=address" \
cargo +nightly fuzz run fuzz_html_parser -- \
  -max_total_time=600 \
  -detect_leaks=1
```

### Run with Coverage Tracking
```bash
cargo +nightly fuzz run fuzz_api_deserializers -- \
  -max_total_time=600 \
  -print_coverage=1 \
  -print_final_stats=1
```

### Limit Memory Usage
```bash
cargo +nightly fuzz run fuzz_api_deserializers -- \
  -max_total_time=600 \
  -rss_limit_mb=2048
```

---

## Summary

**Fastest way to run all tests:**
```bash
cd /home/admin/code/veracode-workspace/fuzz && ./run_all_fuzz_tests.sh
```

**Quick security check (high priority only, 6 minutes total):**
```bash
cd /home/admin/code/veracode-workspace/fuzz && ./run_all_fuzz_tests.sh 120 quick
```

**Comprehensive overnight test:**
```bash
cd /home/admin/code/veracode-workspace/fuzz && nohup ./run_all_fuzz_tests.sh 28800 comprehensive > overnight.log 2>&1 &
```
