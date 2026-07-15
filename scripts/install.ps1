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
#   $env:KIN_HOME = "$HOME\.kin" Install directory (preferred; default: ~/.kin)
#   $env:KIN_DIR = "$HOME\.kin"  Install directory compatibility alias
#   $env:KIN_NO_SETUP = "1"     Skip interactive setup after install
#   $env:KIN_BASE_URL = "..."   Install from a mirror (CI smoke tests / offline)
#
# Note: the native Windows build is a supported vector-free runtime for graph,
# lexical, daemon, setup, and MCP workflows. Vector similarity and filesystem
# projection are unsupported; use WSL2 for the complete experience.

$ErrorActionPreference = "Stop"

# ── Config ──────────────────────────────────────────────────────────────

$KinDir = if ($env:KIN_HOME) {
    $env:KIN_HOME
} elseif ($env:KIN_DIR) {
    $env:KIN_DIR
} else {
    Join-Path $HOME ".kin"
}
$KinBin = Join-Path $KinDir "bin"
$KinLib = Join-Path $KinDir "lib"
$env:KIN_HOME = $KinDir
$env:KIN_DIR = $KinDir
$GitHubOrg = "firelock-ai"
$GitHubRepo = "kin"
# Override KIN_BASE_URL to install from a mirror or a local path (offline /
# airgapped installs and CI smoke tests). Mirrors the install.sh override.
$BaseUrl = if ($env:KIN_BASE_URL) { $env:KIN_BASE_URL } else { "https://github.com/$GitHubOrg/$GitHubRepo/releases" }

# ── Helpers ─────────────────────────────────────────────────────────────

function Write-Info  { Write-Host "  -> $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "  [ok] $args" -ForegroundColor Green }
function Write-Err   { Write-Host "  [error] $args" -ForegroundColor Red }

function Resolve-ArchiveChecksum {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ChecksumContent,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ArchiveName
    )

    $MatchingHashes = @()
    $LineNumber = 0
    foreach ($RawLine in [regex]::Split($ChecksumContent, "\r?\n")) {
        $LineNumber++
        if ([string]::IsNullOrWhiteSpace($RawLine) -or $RawLine.TrimStart().StartsWith("#")) {
            continue
        }

        $Match = [regex]::Match(
            $RawLine,
            '^(?<hash>[0-9a-fA-F]{64})[ \t]+(?<filename>\*?.+?)$',
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        if (-not $Match.Success) {
            throw "Checksum file contains malformed entry on line $LineNumber"
        }

        $Filename = $Match.Groups["filename"].Value
        if ($Filename.StartsWith("*")) {
            $Filename = $Filename.Substring(1)
        }
        if ($Filename -cne $ArchiveName) {
            continue
        }

        $MatchingHashes += $Match.Groups["hash"].Value.ToLowerInvariant()
    }

    if ($MatchingHashes.Count -eq 0) {
        throw "Checksum file has no entry for exact archive '$ArchiveName'"
    }

    $UniqueHashes = @($MatchingHashes | Sort-Object -Unique)
    if ($UniqueHashes.Count -gt 1) {
        throw "Checksum file has conflicting entries for exact archive '$ArchiveName'"
    }

    return $UniqueHashes[0]
}

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

# The native Windows binary is a supported subset: it is vector-free
# (semantic vector similarity disabled) and does NOT provide the transparent filesystem
# projection. Projection relies on Unix library-injection (LD_PRELOAD /
# DYLD_INSERT_LIBRARIES), which native Windows does not offer. For the complete,
# vector-enabled Kin with working projection, install under WSL2 instead — see
# docs/windows-wsl2.md.
Write-Host "  ! Native Windows supports graph + lexical workflows; vector similarity and filesystem projection are unavailable." -ForegroundColor Yellow
Write-Host "    For the full experience, install under WSL2 (see docs/windows-wsl2.md)." -ForegroundColor DarkGray
Write-Host ""

# ── Detect an existing install (reinstall / upgrade) ──────────────────

$PreviousVersion = $null
$ExistingKinExe = Join-Path $KinBin "kin.exe"
if (Test-Path $ExistingKinExe) {
    $PreviousVersion = (& $ExistingKinExe --version 2>$null | Select-Object -First 1)
    if ($PreviousVersion) {
        Write-Info "Existing install found: kin $PreviousVersion (will be replaced)"
    } else {
        Write-Info "Existing install found in $KinDir (will be replaced)"
    }
}

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
# in standard "<hash>  <archive>" format. Download it and fail loudly if it
# is missing, malformed, ambiguous, or does not match — never install an
# unverified download.

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
try {
    $ExpectedHash = Resolve-ArchiveChecksum -ChecksumContent $ChecksumContent -ArchiveName $Archive
} catch {
    Write-Err "Checksum file is invalid: $ChecksumUrl"
    Write-Err $_.Exception.Message
    Write-Err "Refusing to install an unverified download. Aborting."
    exit 1
}

$ActualHash = (Get-FileHash -Path (Join-Path $TmpDir $Archive) -Algorithm SHA256).Hash.ToLowerInvariant()
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

# kin-daemon is mandatory — kin status/search and the MCP server all require it.
# Assert it is present BEFORE moving anything so a daemon-less archive aborts
# cleanly instead of leaving a half-installed environment.
if (-not (Test-Path (Join-Path $TmpDir "kin-daemon.exe"))) {
    Write-Err "kin-daemon.exe missing from the downloaded archive. Refusing a daemon-less install."
    exit 1
}

# Use the downloaded binary's content-free registry-authority contract before
# replacing an installed binary. On Windows the Unix ownership/mode portion is
# reported as not applicable; unsafe supported states still fail closed.
$RegistryArgs = @("registry", "authority")
if ($env:KIN_REGISTRY_REPAIR -eq "1") {
    $RegistryArgs += "--fix"
}
$RegistryCheck = Start-Process -FilePath (Join-Path $TmpDir "kin.exe") `
    -ArgumentList $RegistryArgs -Wait -NoNewWindow -PassThru
if ($RegistryCheck.ExitCode -ne 0) {
    Write-Err "Unsafe local registry authority blocks installation."
    Write-Err "No installed binary or registry authority file was replaced."
    Write-Err "Inspect the paths above. For permission-only drift, rerun with KIN_REGISTRY_REPAIR=1."
    exit 1
}

# Move binaries. kin-daemon.exe is mandatory (asserted above); kin-vfs.exe ships
# only when the archive includes the (Unix-only) projection client.
$HaveVfs = $false
foreach ($bin in @("kin.exe", "kin-daemon.exe", "kin-vfs.exe")) {
    $src = Join-Path $TmpDir $bin
    if (Test-Path $src) {
        Move-Item -Path $src -Destination (Join-Path $KinBin $bin) -Force
        if ($bin -eq "kin-vfs.exe") { $HaveVfs = $true }
    }
}

# Move the projection shim if the archive bundled it. The native Windows release
# is vector-free and ships no shim, so this is normally absent.
$HaveShim = $false
$shimSrc = Join-Path $TmpDir "kin_vfs_shim.dll"
if (Test-Path $shimSrc) {
    Move-Item -Path $shimSrc -Destination (Join-Path $KinLib "kin_vfs_shim.dll") -Force
    $HaveShim = $true
}

Write-Ok "Binaries installed (kin, kin-daemon)"

if ($HaveVfs -and $HaveShim) {
    Write-Ok "Filesystem projection installed (kin-vfs + shim)"
} else {
    Write-Info "Filesystem projection is not available on native Windows. Use WSL2 for projection (see docs/windows-wsl2.md)."
}

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
    $InstalledVersion = (& $KinExe --version 2>$null | Select-Object -First 1)
    if ($PreviousVersion -and $InstalledVersion -and ($PreviousVersion -ne $InstalledVersion)) {
        Write-Ok "kin upgraded: $PreviousVersion -> $InstalledVersion"
    } else {
        Write-Ok "kin $InstalledVersion"
    }
} else {
    Write-Err "Installation failed: kin.exe not found"
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
