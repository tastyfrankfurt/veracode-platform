#!/bin/bash
# Test edge cases discovered by fuzzer

cd ../veraaudit

echo "Testing edge cases discovered by fuzzer..."
echo ""

# Test unicode spaces (non-breaking space U+00A0)
echo "=== Test 1: Non-breaking spaces ==="
echo -e "Input: ' \u00A0 2025-01-15\u00A0 '"
cargo run --quiet -- run --start "$(printf '\u00A0 2025-01-15\u00A0')" --end "2025-01-16" --utc 2>&1 | head -5
echo ""

# Test newlines in input
echo "=== Test 2: Embedded newlines ==="
echo "Input: '2025-01-15\n\n'"
cargo run --quiet -- run --start "$(printf '2025-01-15\n\n')" --end "2025-01-16" --utc 2>&1 | head -5
echo ""

# Test partial dates
echo "=== Test 3: Partial date (1-0) ==="
cargo run --quiet -- run --start "1-0" --end "2025-01-16" --utc 2>&1 | head -5
echo ""

# Test mixed content
echo "=== Test 4: Date with invalid suffix ==="
cargo run --quiet -- run --start "2025-01-15X" --end "2025-01-16" --utc 2>&1 | head -5
echo ""

# Test just whitespace
echo "=== Test 5: Just spaces ==="
cargo run --quiet -- run --start "    " --end "2025-01-16" --utc 2>&1 | head -5
echo ""

echo "Done!"
