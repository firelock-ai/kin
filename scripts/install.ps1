# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Kin installer for Windows — installs the repository-free native CLI surface.
#
# Usage:
#   irm https://get.kinlab.dev/install.ps1 | iex
#
# Options (via env vars):
#   $env:KIN_VERSION = "0.1.0"   Pin a specific version (default: latest)
#   $env:KIN_HOME = "$HOME\.kin" Install directory (preferred; default: ~/.kin)
#   $env:KIN_DIR = "$HOME\.kin"  Install directory compatibility alias
#   $env:KIN_NO_SETUP = "1"     CI compatibility; native repository setup is always skipped
#   $env:KIN_BASE_URL = "..."   Install from a mirror (CI smoke tests / offline)
#
# Native Windows cannot currently admit a repository. The executable refusal
# contract in scripts/assert-windows-init-contract.sh owns the exact public
# support notice copied below; release authority fails if the copies drift.

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

$NativeWindowsSupportNotice = "Native Windows x86_64 can install and run repository-free CLI diagnostics, but repository admission is currently unavailable: kin init fails closed, so graph, lexical, daemon, repository setup, MCP, and review workflows are unsupported. Use WSL2 for usable Kin repositories."

function Resolve-KinWindowsArchiveArchitecture {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProcessArchitecture,

        [Parameter(Mandatory = $true)]
        [bool]$Is64BitProcess
    )

    if (-not $Is64BitProcess) {
        throw "32-bit PowerShell is not supported. Re-run from x64 PowerShell or use WSL2."
    }

    switch ($ProcessArchitecture.ToUpperInvariant()) {
        # Windows-on-ARM reports AMD64 to an x64 PowerShell process, which is
        # exactly the emulation lane the published x86_64 archive supports.
        "AMD64" { return "x86_64" }
        "ARM64" { throw "No native Windows ARM64 archive is published. Use WSL2, or run x64 PowerShell under Windows x64 emulation to install the x86_64 archive." }
        default { throw "Unsupported Windows process architecture '$ProcessArchitecture'. Use x64 PowerShell or WSL2." }
    }
}

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

$Arch = $null
try {
    $Arch = Resolve-KinWindowsArchiveArchitecture `
        -ProcessArchitecture ([string]$env:PROCESSOR_ARCHITECTURE) `
        -Is64BitProcess ([Environment]::Is64BitProcess)
} catch {
    Write-Err $_.Exception.Message
    exit 1
}

$Target = "windows-$Arch"

Write-Host ""
Write-Host "  Kin Installer" -ForegroundColor Cyan -NoNewline
Write-Host " (Windows)" -ForegroundColor DarkGray
Write-Host "  Repository-free CLI diagnostics"
Write-Host ""

Write-Info "Platform: windows ($Arch)"

# The notice is intentionally complete rather than a vague "smaller subset":
# without repository admission there is no supported native graph workflow.
Write-Host "  ! $NativeWindowsSupportNotice" -ForegroundColor Yellow
Write-Host "    Details: https://github.com/firelock-ai/kin/blob/main/docs/windows-wsl2.md" -ForegroundColor DarkGray
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

# kin-daemon remains a mandatory release component even though repository-backed
# daemon workflows are unavailable on native Windows today. Assert the archive
# shape before moving anything so every install stays exact and upgrade-safe.
if (-not (Test-Path (Join-Path $TmpDir "kin-daemon.exe"))) {
    Write-Err "kin-daemon.exe missing from the downloaded archive. Refusing a daemon-less install."
    exit 1
}

# Report the downloaded binary's registry-authority capability before replacing
# an installed binary. Windows currently reports the Unix ownership/mode
# contract as not applicable; it does not claim to repair Windows ACLs.
$RegistryArgs = @("registry", "authority", "--json")
$RegistryCheck = Start-Process -FilePath (Join-Path $TmpDir "kin.exe") `
    -ArgumentList $RegistryArgs -Wait -NoNewWindow -PassThru
if ($RegistryCheck.ExitCode -ne 0) {
    Write-Err "Registry authority capability check failed."
    Write-Err "No installed binary was replaced."
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
    Write-Info "Skipping repository-free setup diagnostics (KIN_NO_SETUP=1)."
} else {
    Write-Host ""
    Write-Info "Not running repository setup: native Windows cannot admit a Kin repository."
    Write-Info "Install inside WSL2 before configuring repository or MCP workflows."
}

# ── Cleanup ─────────────────────────────────────────────────────────────

Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Ok "Done! Restart your terminal to use repository-free CLI diagnostics."
Write-Host "  Use WSL2 for Kin repository workflows: https://github.com/firelock-ai/kin/blob/main/docs/windows-wsl2.md" -ForegroundColor Yellow
Write-Host ""
