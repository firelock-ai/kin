# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Kin installer for Windows — one command to install the full semantic development environment.
#
# Usage:
#   irm https://kinlab.dev/install.ps1 | iex
#
# Options (via env vars):
#   $env:KIN_VERSION = "0.1.0"   Pin a specific version (default: latest)
#   $env:KIN_DIR = "$HOME\.kin"  Install directory (default: ~/.kin)
#   $env:KIN_NO_SETUP = "1"     Skip interactive setup after install

$ErrorActionPreference = "Stop"

# ── Config ──────────────────────────────────────────────────────────────

$KinDir = if ($env:KIN_DIR) { $env:KIN_DIR } else { Join-Path $HOME ".kin" }
$KinBin = Join-Path $KinDir "bin"
$KinLib = Join-Path $KinDir "lib"
$GitHubOrg = "firelock-ai"
$GitHubRepo = "kin"
$BaseUrl = "https://github.com/$GitHubOrg/$GitHubRepo/releases"

# ── Helpers ─────────────────────────────────────────────────────────────

function Write-Info  { Write-Host "  → $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "  ✓ $args" -ForegroundColor Green }
function Write-Err   { Write-Host "  ✗ $args" -ForegroundColor Red }

# ── Detect architecture ─────────────────────────────────────────────────

$Arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
} else {
    Write-Err "32-bit systems are not supported"
    exit 1
}

$Target = "windows-$Arch"

Write-Host ""
Write-Host "  Kin Installer" -ForegroundColor Cyan -NoNewline
Write-Host " (Windows)" -ForegroundColor DarkGray
Write-Host "  Semantic development environment"
Write-Host ""

Write-Info "Platform: windows ($Arch)"

# ── Resolve version ─────────────────────────────────────────────────────

if ($env:KIN_VERSION) {
    $Version = $env:KIN_VERSION
    Write-Info "Version: $Version (pinned)"
} else {
    Write-Info "Fetching latest version..."
    $Release = Invoke-RestMethod "https://api.github.com/repos/$GitHubOrg/$GitHubRepo/releases/latest"
    $Version = $Release.tag_name -replace '^v', ''
    if (-not $Version) {
        Write-Err "Could not determine latest version"
        exit 1
    }
    Write-Info "Version: $Version (latest)"
}

# ── Download ────────────────────────────────────────────────────────────

$Archive = "kin-v$Version-$Target.zip"
$Url = "$BaseUrl/download/v$Version/$Archive"

Write-Info "Downloading $Archive..."

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "kin-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    Invoke-WebRequest -Uri $Url -OutFile (Join-Path $TmpDir $Archive) -UseBasicParsing
} catch {
    Write-Err "Download failed: $_"
    exit 1
}

# ── Extract ─────────────────────────────────────────────────────────────

Write-Info "Installing to $KinDir..."

New-Item -ItemType Directory -Path $KinBin -Force | Out-Null
New-Item -ItemType Directory -Path $KinLib -Force | Out-Null

Expand-Archive -Path (Join-Path $TmpDir $Archive) -DestinationPath $TmpDir -Force

# Move binaries
foreach ($bin in @("kin.exe", "kin-vfs.exe")) {
    $src = Join-Path $TmpDir $bin
    if (Test-Path $src) {
        Move-Item -Path $src -Destination (Join-Path $KinBin $bin) -Force
    }
}

# Move shim library
$shimSrc = Join-Path $TmpDir "kin_vfs_shim.dll"
if (Test-Path $shimSrc) {
    Move-Item -Path $shimSrc -Destination (Join-Path $KinLib "kin_vfs_shim.dll") -Force
}

Write-Ok "Binaries installed"

# ── PATH setup ──────────────────────────────────────────────────────────

$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notlike "*$KinBin*") {
    [Environment]::SetEnvironmentVariable("Path", "$KinBin;$CurrentPath", "User")
    $env:Path = "$KinBin;$env:Path"
    Write-Ok "Added $KinBin to user PATH"
} else {
    Write-Ok "PATH already configured"
}

# ── Verify ──────────────────────────────────────────────────────────────

$KinExe = Join-Path $KinBin "kin.exe"
if (Test-Path $KinExe) {
    $ver = & $KinExe --version 2>$null
    Write-Ok "kin $ver"
} else {
    Write-Err "Installation failed — kin.exe not found"
    exit 1
}

# ── Run setup ───────────────────────────────────────────────────────────

if ($env:KIN_NO_SETUP -eq "1") {
    Write-Host ""
    Write-Info "Skipping setup (KIN_NO_SETUP=1). Run 'kin setup' when ready."
} else {
    Write-Host ""
    & $KinExe setup
}

# ── Cleanup ─────────────────────────────────────────────────────────────

Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Ok "Done! Restart your terminal to get started."
Write-Host ""
