# Cross-platform build script for verascan (PowerShell version)
# Supports Linux, Windows, and macOS (Intel and Apple Silicon)

param(
    [string]$Target = "",
    [switch]$All = $false,
    [switch]$Debug = $false,
    [switch]$Help = $false
)

# Available targets
$Targets = @{
    "x86_64-unknown-linux-gnu" = "Linux x64"
    "x86_64-pc-windows-msvc" = "Windows x64"
    "x86_64-apple-darwin" = "macOS Intel"
    "aarch64-apple-darwin" = "macOS Apple Silicon"
}

$BuildMode = if ($Debug) { "debug" } else { "release" }
$Package = "verascan"

function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Show-Help {
    Write-Host "Cross-platform build script for verascan"
    Write-Host ""
    Write-Host "Usage: .\build.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Target TARGET     Build for specific target (see list below)"
    Write-Host "  -All              Build for all supported targets"
    Write-Host "  -Debug            Build in debug mode (default: release)"
    Write-Host "  -Help             Show this help message"
    Write-Host ""
    Write-Host "Available targets:"
    foreach ($target in $Targets.GetEnumerator()) {
        Write-Host "  $($target.Key.PadRight(25)) $($target.Value)"
    }
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\build.ps1 -All                           # Build for all targets"
    Write-Host "  .\build.ps1 -Target x86_64-apple-darwin    # Build for macOS Intel"
    Write-Host "  .\build.ps1 -Target aarch64-apple-darwin   # Build for macOS Apple Silicon"
    Write-Host "  .\build.ps1 -Debug -All                    # Build debug version for all targets"
}

function Test-Rust {
    if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
        Write-Error "Rust is not installed. Please install Rust from https://rustup.rs/"
        exit 1
    }
    
    $rustVersion = rustc --version
    Write-Status "Rust version: $rustVersion"
}

function Install-Target {
    param([string]$TargetName)
    
    Write-Status "Checking if target $TargetName is installed..."
    
    $installedTargets = rustup target list --installed
    if ($installedTargets -notcontains $TargetName) {
        Write-Status "Installing target $TargetName..."
        rustup target add $TargetName
    } else {
        Write-Status "Target $TargetName is already installed"
    }
}

function Build-Target {
    param(
        [string]$TargetName,
        [string]$Description
    )
    
    $outputDir = "target\$TargetName\$BuildMode"
    $binaryName = "verascan"
    
    # Add .exe extension for Windows
    if ($TargetName -like "*windows*") {
        $binaryName = "verascan.exe"
    }
    
    Write-Status "Building $Description ($TargetName)..."
    
    # Install target if needed
    Install-Target $TargetName
    
    # Build the project
    try {
        if ($BuildMode -eq "debug") {
            cargo build --target $TargetName -p $Package
        } else {
            cargo build --release --target $TargetName -p $Package
        }
    } catch {
        Write-Error "Build failed for $Description ($TargetName)"
        return $false
    }
    
    # Check if build was successful
    $binaryPath = "$outputDir\$binaryName"
    if (Test-Path $binaryPath) {
        $fileSize = (Get-Item $binaryPath).Length
        $fileSizeFormatted = if ($fileSize -gt 1MB) { 
            "{0:N1} MB" -f ($fileSize / 1MB) 
        } else { 
            "{0:N1} KB" -f ($fileSize / 1KB) 
        }
        
        Write-Success "Built $Description`: $binaryPath ($fileSizeFormatted)"
        
        # Create a copy with a descriptive name
        $artifactName = switch ($TargetName) {
            "x86_64-unknown-linux-gnu" { "verascan-linux-x64" }
            "x86_64-pc-windows-msvc" { "verascan-windows-x64.exe" }
            "x86_64-apple-darwin" { "verascan-macos-x64" }
            "aarch64-apple-darwin" { "verascan-macos-arm64" }
            default { "verascan-$TargetName" }
        }
        
        # Create dist directory and copy artifact
        if (-not (Test-Path "dist")) {
            New-Item -ItemType Directory -Path "dist" | Out-Null
        }
        
        Copy-Item $binaryPath "dist\$artifactName"
        Write-Success "Artifact created: dist\$artifactName"
        return $true
    } else {
        Write-Error "Build failed for $Description ($TargetName)"
        return $false
    }
}

function Build-All {
    Write-Status "Building for all supported targets..."
    
    $failedBuilds = @()
    
    foreach ($target in $Targets.GetEnumerator()) {
        if (-not (Build-Target $target.Key $target.Value)) {
            $failedBuilds += $target.Key
        }
        Write-Host "" # Add spacing between builds
    }
    
    # Report results
    if ($failedBuilds.Count -eq 0) {
        Write-Success "All builds completed successfully!"
        return $true
    } else {
        Write-Warning "Some builds failed: $($failedBuilds -join ', ')"
        return $false
    }
}

function Main {
    if ($Help) {
        Show-Help
        return
    }
    
    Write-Status "Verascan Cross-Platform Build Script"
    Write-Status "Build mode: $BuildMode"
    Write-Host ""
    
    # Check prerequisites
    Test-Rust
    
    # Clean dist directory
    if (Test-Path "dist") {
        Remove-Item "dist" -Recurse -Force
    }
    New-Item -ItemType Directory -Path "dist" | Out-Null
    
    if ($All) {
        $success = Build-All
    } elseif ($Target) {
        if (-not $Targets.ContainsKey($Target)) {
            Write-Error "Unknown target: $Target"
            Write-Status "Available targets:"
            foreach ($t in $Targets.GetEnumerator()) {
                Write-Host "  $($t.Key) - $($t.Value)"
            }
            exit 1
        }
        
        $success = Build-Target $Target $Targets[$Target]
    } else {
        Write-Error "No target specified. Use -All to build for all targets or -Target to specify a target."
        Show-Help
        exit 1
    }
    
    if ($success) {
        Write-Success "Build script completed!"
        Write-Status "Artifacts available in the 'dist' directory"
    } else {
        Write-Error "Build script completed with errors!"
        exit 1
    }
}

# Run main function
Main