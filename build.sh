#!/bin/bash

# Cross-platform build script for verascan
# Supports Linux, Windows, and macOS (Intel and Apple Silicon)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Available targets
TARGETS=(
    "x86_64-unknown-linux-gnu:Linux x64 (glibc)"
    "x86_64-unknown-linux-musl:Linux x64 (musl/Alpine)"
    "x86_64-pc-windows-msvc:Windows x64"
    "x86_64-apple-darwin:macOS Intel"
    "aarch64-apple-darwin:macOS Apple Silicon"
)

# Default build mode
BUILD_MODE="release"
PACKAGE="verascan"

# Parse command line arguments
show_help() {
    echo "Cross-platform build script for verascan"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --target TARGET     Build for specific target (see list below)"
    echo "  -a, --all              Build for all supported targets"
    echo "  -d, --debug            Build in debug mode (default: release)"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Available targets:"
    for target in "${TARGETS[@]}"; do
        IFS=':' read -r target_name description <<< "$target"
        printf "  %-25s %s\n" "$target_name" "$description"
    done
    echo ""
    echo "Examples:"
    echo "  $0 --all                           # Build for all targets"
    echo "  $0 --target x86_64-apple-darwin    # Build for macOS Intel"
    echo "  $0 --target aarch64-apple-darwin   # Build for macOS Apple Silicon"
    echo "  $0 --debug --all                   # Build debug version for all targets"
}

# Check if Rust is installed
check_rust() {
    if ! command -v rustc &> /dev/null; then
        print_error "Rust is not installed. Please install Rust from https://rustup.rs/"
        exit 1
    fi
    
    print_status "Rust version: $(rustc --version)"
}

# Install target if not already installed
install_target() {
    local target=$1
    print_status "Checking if target $target is installed..."
    
    if ! rustup target list --installed | grep -q "^$target$"; then
        print_status "Installing target $target..."
        rustup target add "$target"
    else
        print_status "Target $target is already installed"
    fi
}

# Build for a specific target
build_target() {
    local target=$1
    local description=$2
    local output_dir="target/$target/$BUILD_MODE"
    local binary_name="verascan"
    
    # Add .exe extension for Windows
    if [[ $target == *"windows"* ]]; then
        binary_name="verascan.exe"
    fi
    
    print_status "Building $description ($target)..."
    
    # Install target if needed
    install_target "$target"
    
    # Build the project with platform-specific optimizations
    if [[ $target == "x86_64-unknown-linux-gnu" ]]; then
        print_status "Using static linking for glibc (requires static libraries)"
    elif [[ $target == "x86_64-unknown-linux-musl" ]]; then
        print_status "Using musl static linking for Alpine compatibility"
    else
        print_status "Using dynamic linking for $target"
    fi
    
    if [ "$BUILD_MODE" = "debug" ]; then
        cargo build --target "$target" -p "$PACKAGE"
    else
        cargo build --release --target "$target" -p "$PACKAGE"
    fi
    
    # Check if build was successful
    if [ -f "$output_dir/$binary_name" ]; then
        local file_size=$(du -h "$output_dir/$binary_name" | cut -f1)
        print_success "Built $description: $output_dir/$binary_name ($file_size)"
        
        # Create a copy with a descriptive name
        local artifact_name
        case $target in
            "x86_64-unknown-linux-gnu")
                artifact_name="verascan-linux-x64-glibc"
                ;;
            "x86_64-unknown-linux-musl")
                artifact_name="verascan-linux-x64-musl"
                ;;
            "x86_64-pc-windows-msvc")
                artifact_name="verascan-windows-x64.exe"
                ;;
            "x86_64-apple-darwin")
                artifact_name="verascan-macos-x64"
                ;;
            "aarch64-apple-darwin")
                artifact_name="verascan-macos-arm64"
                ;;
            *)
                artifact_name="verascan-$target"
                ;;
        esac
        
        # Create dist directory and copy artifact
        mkdir -p dist
        cp "$output_dir/$binary_name" "dist/$artifact_name"
        print_success "Artifact created: dist/$artifact_name"
    else
        print_error "Build failed for $description ($target)"
        return 1
    fi
}

# Build for all targets
build_all() {
    print_status "Building for all supported targets..."
    
    local failed_builds=()
    
    for target in "${TARGETS[@]}"; do
        IFS=':' read -r target_name description <<< "$target"
        
        if ! build_target "$target_name" "$description"; then
            failed_builds+=("$target_name")
        fi
        echo "" # Add spacing between builds
    done
    
    # Report results
    if [ ${#failed_builds[@]} -eq 0 ]; then
        print_success "All builds completed successfully!"
    else
        print_warning "Some builds failed: ${failed_builds[*]}"
        return 1
    fi
}

# Parse command line arguments
TARGET=""
BUILD_ALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -a|--all)
            BUILD_ALL=true
            shift
            ;;
        -d|--debug)
            BUILD_MODE="debug"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_status "Verascan Cross-Platform Build Script"
    print_status "Build mode: $BUILD_MODE"
    echo ""
    
    # Check prerequisites
    check_rust
    
    # Clean dist directory
    rm -rf dist
    mkdir -p dist
    
    if [ "$BUILD_ALL" = true ]; then
        build_all
    elif [ -n "$TARGET" ]; then
        # Find the description for the target
        description=""
        for target in "${TARGETS[@]}"; do
            IFS=':' read -r target_name target_desc <<< "$target"
            if [ "$target_name" = "$TARGET" ]; then
                description="$target_desc"
                break
            fi
        done
        
        if [ -z "$description" ]; then
            print_error "Unknown target: $TARGET"
            print_status "Available targets:"
            for target in "${TARGETS[@]}"; do
                IFS=':' read -r target_name target_desc <<< "$target"
                echo "  $target_name - $target_desc"
            done
            exit 1
        fi
        
        build_target "$TARGET" "$description"
    else
        print_error "No target specified. Use --all to build for all targets or --target to specify a target."
        show_help
        exit 1
    fi
    
    print_success "Build script completed!"
    print_status "Artifacts available in the 'dist' directory"
}

# Run main function
main