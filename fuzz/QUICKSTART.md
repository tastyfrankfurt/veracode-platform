# Fuzzing Quick Start Guide

This guide provides quick commands to start fuzzing the Veracode workspace immediately.

## Prerequisites

```bash
# Install Rust nightly (if not already installed)
rustup install nightly

# Install cargo-fuzz (if not already installed)
cargo install cargo-fuzz
```

## Quick Test (2 minutes each)

Run high-priority security targets for a quick smoke test:

```bash
cd /home/admin/code/veracode-workspace

# Test URL/CMEK validators (SSRF, injection risk)
cargo +nightly fuzz run fuzz_verascan_validators -- -max_total_time=120

# Test HTML parser (XSS risk)
cargo +nightly fuzz run fuzz_html_parser -- -max_total_time=120

# Test Vault credential parsing (auth bypass risk)
cargo +nightly fuzz run fuzz_vault_parsers -- -max_total_time=120
```

## Standard Test (10 minutes each)

Run all new fuzz targets for a comprehensive test:

```bash
cd /home/admin/code/veracode-workspace

# CLI validators (verascan)
cargo +nightly fuzz run fuzz_verascan_validators -- -max_total_time=600 -print_final_stats=1

# API JSON deserializers
cargo +nightly fuzz run fuzz_api_deserializers -- -max_total_time=600 -print_final_stats=1

# HTML tag stripping
cargo +nightly fuzz run fuzz_html_parser -- -max_total_time=600 -print_final_stats=1

# Vault credential parsing
cargo +nightly fuzz run fuzz_vault_parsers -- -max_total_time=600 -print_final_stats=1

# Output file parsing
cargo +nightly fuzz run fuzz_output_parsers -- -max_total_time=600 -print_final_stats=1
```

## Run All Targets (1 hour)

```bash
cd /home/admin/code/veracode-workspace

for target in fuzz_verascan_validators fuzz_api_deserializers fuzz_html_parser \
              fuzz_vault_parsers fuzz_output_parsers fuzz_datetime fuzz_cli_validators; do
    echo "========================================="
    echo "Fuzzing: $target"
    echo "========================================="
    cargo +nightly fuzz run "$target" -- -max_total_time=600 -print_final_stats=1

    # Check for crashes
    if ls fuzz/artifacts/"$target"/* 2>/dev/null; then
        echo ""
        echo "⚠️  CRASHES FOUND in $target!"
        echo "See: fuzz/artifacts/$target/"
    else
        echo "✅ No crashes in $target"
    fi
    echo ""
done
```

## Check for Crashes

```bash
# Quick check
find fuzz/artifacts -type f

# Detailed check
for dir in fuzz/artifacts/*/; do
    if [ "$(ls -A $dir 2>/dev/null)" ]; then
        echo "🚨 CRASHES in $(basename $dir):"
        ls -lah "$dir"
    fi
done
```

## Reproduce a Crash

```bash
# If a crash was found, reproduce it:
cargo +nightly fuzz run <target_name> fuzz/artifacts/<target_name>/crash-<hash>

# Minimize the crashing input:
cargo +nightly fuzz tmin <target_name> fuzz/artifacts/<target_name>/crash-<hash>
```

## Available Fuzz Targets

| Priority | Target | What It Tests |
|----------|--------|---------------|
| 🔴 High | `fuzz_verascan_validators` | 19 CLI validators (URLs, CMEK, names, CWE lists) |
| 🔴 High | `fuzz_html_parser` | HTML tag stripping (XSS prevention) |
| 🔴 High | `fuzz_vault_parsers` | Vault credential parsing (auth security) |
| 🟡 Medium | `fuzz_api_deserializers` | JSON API response parsing (15+ deserializers) |
| 🟡 Medium | `fuzz_datetime` | Datetime parsing with timezone support |
| 🟡 Medium | `fuzz_cli_validators` | Veraaudit CLI validators |
| 🟢 Low | `fuzz_output_parsers` | Log file parsing and timestamp handling |
| 🟢 Low | `fuzz_validation` | Enum FromStr implementations |
| 🟢 Low | `fuzz_combined` | Combined datetime + validation |

## Corpus Statistics

Current seed corpus counts:

- `fuzz_verascan_validators`: 8 seeds
- `fuzz_api_deserializers`: 5 seeds
- `fuzz_html_parser`: 6 seeds
- `fuzz_vault_parsers`: 6 seeds
- `fuzz_output_parsers`: 5 seeds
- `fuzz_datetime`: 57 seeds (existing)
- `fuzz_cli_validators`: 316 seeds (existing)
- `fuzz_validation`: 9 seeds (existing)
- `fuzz_combined`: 44 seeds (existing)

## Understanding Output

```
#12345: cov: 234 ft: 567 corp: 89/12kb exec/s: 1234 rss: 45Mb
```

- `#12345` - Total executions
- `cov: 234` - Code coverage (unique paths)
- `corp: 89/12kb` - Corpus size (89 test cases, 12KB total)
- `exec/s: 1234` - Executions per second
- `rss: 45Mb` - Memory usage

Good signs:
- ✅ Coverage increasing
- ✅ High exec/s (>1000)
- ✅ No crashes

Warning signs:
- ⚠️ Coverage plateaus quickly
- ⚠️ Low exec/s (<100)
- 🚨 Crashes found

## Next Steps

For detailed documentation, see:
- [README.md](./README.md) - Complete fuzzing guide
- [IMPROVEMENTS.md](./IMPROVEMENTS.md) - Findings from fuzzing veraaudit

## Quick Reference Commands

```bash
# List all targets
cargo +nightly fuzz list

# Build all targets (to check for errors)
cargo +nightly fuzz build

# Coverage report
cargo +nightly fuzz coverage <target>

# Minimize corpus
cargo +nightly fuzz cmin <target>
```

---

**Total: 9 fuzz targets covering 65+ security-critical functions**
