# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Kin installer for Windows — one command to install the full semantic development environment.
#
# Usage:
#   irm https://get.kinlab.dev/install.ps1 | iex
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

$Archive = "kin-$Target.zip"
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

# ── Verify checksum ───────────────────────────────────────────────────
# The release workflow publishes "<archive>.sha256" next to every archive
# (Get-FileHash format). Download it and fail loudly if it is missing,
# malformed, or does not match — never install an unverified download.

$ChecksumUrl = "$Url.sha256"
$ChecksumFile = Join-Path $TmpDir "$Archive.sha256"

try {
    Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumFile -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Err "Could not download checksum file: $ChecksumUrl"
    Write-Err "Refusing to install an unverified download. Aborting."
    exit 1
}

$ChecksumContent = Get-Content $ChecksumFile -Raw
# Match the hash on the line referencing this archive; tolerate either a bare
# hash line or "<hash>  <filename>". Hashes are 64 hex chars.
$ExpectedHash = $null
foreach ($line in ($ChecksumContent -split "`n")) {
    if ($line -match '([0-9a-fA-F]{64})') {
        $ExpectedHash = $Matches[1].ToLower()
        break
    }
}

if (-not $ExpectedHash) {
    Write-Err "Checksum file was empty or malformed: $ChecksumUrl"
    Write-Err "Refusing to install an unverified download. Aborting."
    exit 1
}

$ActualHash = (Get-FileHash -Path (Join-Path $TmpDir $Archive) -Algorithm SHA256).Hash.ToLower()
if ($ActualHash -ne $ExpectedHash) {
    Write-Err "SHA-256 checksum mismatch!"
    Write-Err "Expected: $ExpectedHash"
    Write-Err "Got:      $ActualHash"
    Write-Err "The download may be corrupted or tampered with. Aborting."
    exit 1
}
Write-Ok "SHA-256 checksum verified"

# ── Extract ─────────────────────────────────────────────────────────────

Write-Info "Installing to $KinDir..."

New-Item -ItemType Directory -Path $KinBin -Force | Out-Null
New-Item -ItemType Directory -Path $KinLib -Force | Out-Null

Expand-Archive -Path (Join-Path $TmpDir $Archive) -DestinationPath $TmpDir -Force

# FIR-967: kin-daemon is mandatory — kin status/search and the MCP server all
# require it. Assert it is present BEFORE moving anything so a daemon-less
# archive aborts cleanly instead of leaving a half-installed environment.
if (-not (Test-Path (Join-Path $TmpDir "kin-daemon.exe"))) {
    Write-Err "kin-daemon.exe missing from the downloaded archive. Refusing a daemon-less install."
    exit 1
}

# Move binaries. kin-daemon.exe is mandatory (asserted above); kin-vfs.exe is optional.
foreach ($bin in @("kin.exe", "kin-daemon.exe", "kin-vfs.exe")) {
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
