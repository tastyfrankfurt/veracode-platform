#!/bin/bash

# Comprehensive Fuzzing Test Script for Veracode Workspace
# Runs all fuzz targets with configurable duration

set -e

# Configuration
DEFAULT_DURATION=600  # 10 minutes per target
QUICK_DURATION=120    # 2 minutes for quick test
COMPREHENSIVE_DURATION=1800  # 30 minutes for thorough test

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
DURATION=${1:-$DEFAULT_DURATION}
MODE=${2:-"standard"}

# Function to print section headers
print_header() {
    echo ""
    echo "========================================="
    echo -e "${BLUE}$1${NC}"
    echo "========================================="
    echo ""
}

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Function to print error
print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    if ! command -v rustup &> /dev/null; then
        print_error "rustup not found. Please install Rust."
        exit 1
    fi

    if ! rustup toolchain list | grep -q nightly; then
        print_warning "Nightly toolchain not installed. Installing..."
        rustup install nightly
    else
        print_status "Nightly toolchain installed"
    fi

    if ! command -v cargo-fuzz &> /dev/null; then
        print_warning "cargo-fuzz not installed. Installing..."
        cargo install cargo-fuzz
    else
        print_status "cargo-fuzz installed"
    fi
}

# Define fuzz targets with priorities
declare -A TARGETS_HIGH_PRIORITY=(
    ["fuzz_verascan_validators"]="URL/CMEK validators (SSRF, injection risk)"
    ["fuzz_html_parser"]="HTML parser (XSS risk)"
    ["fuzz_vault_parsers"]="Vault credential parsing (auth bypass risk)"
)

declare -A TARGETS_MEDIUM_PRIORITY=(
    ["fuzz_datetime"]="Datetime parsers (timezone/DST bugs)"
    ["fuzz_api_deserializers"]="API deserializers (DoS via nested JSON)"
    ["fuzz_cli_validators"]="Veraaudit CLI validators"
)

declare -A TARGETS_LOW_PRIORITY=(
    ["fuzz_output_parsers"]="Output file parsing"
    ["fuzz_validation"]="Enum FromStr implementations"
    ["fuzz_combined"]="Combined datetime + validation"
)

# Function to run a single fuzz target
run_fuzz_target() {
    local target=$1
    local description=$2
    local duration=$3

    echo ""
    echo "-------------------------------------------------------------------"
    echo -e "${BLUE}Target:${NC} $target"
    echo -e "${BLUE}Description:${NC} $description"
    echo -e "${BLUE}Duration:${NC} ${duration}s ($(($duration / 60)) minutes)"
    echo "-------------------------------------------------------------------"

    # Run the fuzzer
    cargo +nightly fuzz run "$target" -- \
        -max_total_time="$duration" \
        -print_final_stats=1 \
        2>&1 | tee "fuzz_${target}_output.log"

    # Check for crashes
    if ls artifacts/"$target"/* 2>/dev/null; then
        print_error "CRASHES FOUND in $target!"
        echo -e "${RED}See: artifacts/$target/${NC}"
        ls -lah artifacts/"$target"/
        echo "$target" >> crashes_found.txt
    else
        print_status "No crashes in $target"
    fi
}

# Main execution
main() {
    print_header "Veracode Workspace Fuzzing Test Suite"

    echo "Mode: $MODE"
    echo "Duration per target: ${DURATION}s ($(($DURATION / 60)) minutes)"
    echo ""

    # Check prerequisites
    check_prerequisites

    # Clean up old crash report
    rm -f crashes_found.txt

    # Record start time
    START_TIME=$(date +%s)

    # HIGH PRIORITY TARGETS
    print_header "HIGH PRIORITY TARGETS"
    for target in "${!TARGETS_HIGH_PRIORITY[@]}"; do
        run_fuzz_target "$target" "${TARGETS_HIGH_PRIORITY[$target]}" "$DURATION"
    done

    # MEDIUM PRIORITY TARGETS
    if [ "$MODE" != "quick" ]; then
        print_header "MEDIUM PRIORITY TARGETS"
        for target in "${!TARGETS_MEDIUM_PRIORITY[@]}"; do
            run_fuzz_target "$target" "${TARGETS_MEDIUM_PRIORITY[$target]}" "$DURATION"
        done
    fi

    # LOW PRIORITY TARGETS
    if [ "$MODE" == "comprehensive" ]; then
        print_header "LOW PRIORITY TARGETS"
        for target in "${!TARGETS_LOW_PRIORITY[@]}"; do
            run_fuzz_target "$target" "${TARGETS_LOW_PRIORITY[$target]}" "$DURATION"
        done
    fi

    # Record end time
    END_TIME=$(date +%s)
    ELAPSED_TIME=$((END_TIME - START_TIME))
    ELAPSED_MINUTES=$((ELAPSED_TIME / 60))

    # Final Summary
    print_header "FUZZING COMPLETE - SUMMARY"

    echo "Total time elapsed: ${ELAPSED_MINUTES} minutes (${ELAPSED_TIME} seconds)"
    echo ""

    # Count targets run
    case "$MODE" in
        "quick")
            TARGETS_RUN=${#TARGETS_HIGH_PRIORITY[@]}
            ;;
        "comprehensive")
            TARGETS_RUN=$((${#TARGETS_HIGH_PRIORITY[@]} + ${#TARGETS_MEDIUM_PRIORITY[@]} + ${#TARGETS_LOW_PRIORITY[@]}))
            ;;
        *)
            TARGETS_RUN=$((${#TARGETS_HIGH_PRIORITY[@]} + ${#TARGETS_MEDIUM_PRIORITY[@]}))
            ;;
    esac

    echo "Targets run: $TARGETS_RUN"
    echo ""

    # Check for crashes
    if [ -f crashes_found.txt ]; then
        print_error "CRASHES DETECTED!"
        echo ""
        echo "Targets with crashes:"
        cat crashes_found.txt
        echo ""
        echo "Review crash artifacts in the following directories:"
        while read -r target; do
            echo "  - artifacts/$target/"
        done < crashes_found.txt
        echo ""
        print_warning "Action required: Investigate and fix crashes before release"
        exit 1
    else
        print_status "No crashes detected in any target!"
        echo ""
        print_status "All tests passed successfully"
    fi

    # Corpus statistics
    print_header "Corpus Statistics"
    echo "Corpus sizes after fuzzing:"
    for dir in corpus/fuzz_*; do
        if [ -d "$dir" ]; then
            count=$(ls "$dir" 2>/dev/null | wc -l)
            printf "  %-35s %5d seeds\n" "$(basename "$dir"):" "$count"
        fi
    done

    echo ""
    print_status "Fuzzing logs saved to fuzz_*_output.log"
    echo ""
}

# Show usage information
show_usage() {
    cat << EOF
Usage: $0 [DURATION] [MODE]

Arguments:
    DURATION    Time in seconds per target (default: 600 = 10 minutes)
    MODE        Testing mode (default: standard)
                - quick: High priority targets only
                - standard: High + medium priority targets
                - comprehensive: All targets

Examples:
    # Quick test (2 minutes per target, high priority only)
    $0 120 quick

    # Standard test (10 minutes per target, high + medium priority)
    $0 600 standard

    # Comprehensive test (30 minutes per target, all targets)
    $0 1800 comprehensive

    # Custom duration, standard mode
    $0 300

Priority Levels:
    HIGH (3 targets):
        - fuzz_verascan_validators (URL/CMEK validators)
        - fuzz_html_parser (HTML parser - XSS risk)
        - fuzz_vault_parsers (Vault credential parsing)

    MEDIUM (3 targets):
        - fuzz_datetime (Datetime parsing)
        - fuzz_api_deserializers (JSON/XML deserializers)
        - fuzz_cli_validators (CLI validators)

    LOW (3 targets):
        - fuzz_output_parsers (File parsing)
        - fuzz_validation (Enum parsing)
        - fuzz_combined (Combined tests)

EOF
}

# Check for help flag
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    show_usage
    exit 0
fi

# Run main function
main
