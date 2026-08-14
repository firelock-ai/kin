# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Kin installer for Windows — installs the repository-free native CLI surface.
#
# Usage:
#   irm https://get.kinlab.dev/install.ps1 | iex
#
# Options (via env vars):
#   $env:KIN_VERSION = "0.5.25"  Pin a specific version (default: latest)
#   $env:KIN_HOME = "$HOME\.kin" Install directory (preferred; default: ~/.kin)
#   $env:KIN_DIR = "$HOME\.kin"  Install directory compatibility alias
#   $env:KIN_NO_SETUP = "1"     CI compatibility; native repository setup is always skipped
#   $env:KIN_BASE_URL = "..."   Install from a mirror (CI smoke tests / offline)
#
# Native Windows admits repositories; scripts/assert-windows-init-contract.sh
# proves both admission boundaries on every pull request. The
# $NativeWindowsSupportNotice binding below owns the exact public support
# notice, and release authority fails if any shipped copy of it drifts.

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
function Test-KinTruthy([string]$Value) {
    if ($null -eq $Value) { return $false }
    return @("1", "true", "yes", "on") -contains $Value.Trim().ToLowerInvariant()
}

$NativeWindowsSupportNotice = "Native Windows x86_64 support is early. Repository admission works: kin init imports a Git repository and publishes graph authority, and graph, lexical, and daemon-backed queries answer natively. Transparent filesystem projection is not shipped on Windows, and the end-to-end install proof does not yet cover MCP or review workflows there, so WSL2 remains the recommended path for the full Kin experience. If kin init reports that tracked bytes differ from the committed tree, Git for Windows checked the repository out with core.autocrlf=true from its system config; run 'git config --global core.autocrlf false' and clone again."

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

function Format-ByteCount {
    param(
        [Parameter(Mandatory = $true)]
        [long]$Bytes
    )

    $Invariant = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return "{0} KiB" -f (($Bytes / 1KB).ToString("0.0", $Invariant)) }
    if ($Bytes -lt 1GB) { return "{0} MiB" -f (($Bytes / 1MB).ToString("0.0", $Invariant)) }
    return "{0} GiB" -f (($Bytes / 1GB).ToString("0.0", $Invariant))
}

function Invoke-ArchiveDownload {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutFile,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ArchiveName,

        [switch]$ShowProgress
    )

    # ResponseHeadersRead lets the installer report the archive as it arrives
    # instead of buffering the entire release before showing any movement.
    $Client = $null
    $Response = $null
    $InputStream = $null
    $OutputStream = $null
    try {
        $LocalPath = $null
        if ($Uri -match '^file:') {
            $LocalPath = ([Uri]$Uri).LocalPath
        } elseif ($Uri -notmatch '^https?://' -and (Test-Path -LiteralPath $Uri)) {
            $LocalPath = (Resolve-Path -LiteralPath $Uri).Path
        }

        if ($null -ne $LocalPath) {
            $InputStream = [System.IO.File]::OpenRead($LocalPath)
            $TotalBytes = $InputStream.Length
        } else {
            Add-Type -AssemblyName System.Net.Http
            $Client = [System.Net.Http.HttpClient]::new()
            $Client.Timeout = [TimeSpan]::FromMinutes(30)
            $Client.DefaultRequestHeaders.UserAgent.ParseAdd("Kin-Installer")
            $Response = $Client.GetAsync(
                $Uri,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
            ).GetAwaiter().GetResult()
            $Response.EnsureSuccessStatusCode() | Out-Null
            $TotalBytes = $Response.Content.Headers.ContentLength
            $InputStream = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        }

        $OutputStream = [System.IO.File]::Open(
            $OutFile,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $Buffer = [byte[]]::new(1024 * 1024)
        [long]$ReceivedBytes = 0

        while (($Read = $InputStream.ReadAsync($Buffer, 0, $Buffer.Length).GetAwaiter().GetResult()) -gt 0) {
            $OutputStream.Write($Buffer, 0, $Read)
            $ReceivedBytes += $Read
            if ($ShowProgress) {
                if ($null -ne $TotalBytes -and $TotalBytes -gt 0) {
                    $Percent = [Math]::Min(100, [Math]::Floor(($ReceivedBytes * 100.0) / $TotalBytes))
                    $Status = "{0}% ({1} / {2})" -f (
                        $Percent,
                        (Format-ByteCount $ReceivedBytes),
                        (Format-ByteCount $TotalBytes)
                    )
                    Write-Progress -Activity "Downloading $ArchiveName" -Status $Status -PercentComplete $Percent
                } else {
                    $Status = "{0} received" -f (Format-ByteCount $ReceivedBytes)
                    Write-Progress -Activity "Downloading $ArchiveName" -Status $Status -PercentComplete -1
                }
            }
        }
    } finally {
        if ($ShowProgress) {
            Write-Progress -Activity "Downloading $ArchiveName" -Completed
        }
        if ($null -ne $OutputStream) { $OutputStream.Dispose() }
        if ($null -ne $InputStream) { $InputStream.Dispose() }
        if ($null -ne $Response) { $Response.Dispose() }
        if ($null -ne $Client) { $Client.Dispose() }
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
# `irm ... | iex` still has a real ConsoleHost, so first installs launched from
# the documented one-liner get live byte/percent feedback. Redirected and CI
# hosts skip progress records while preserving the exact same download bytes.
$ShowArchiveProgress = $Host.Name -eq "ConsoleHost"
try {
    $ShowArchiveProgress = $ShowArchiveProgress -and -not [Console]::IsOutputRedirected
} catch {
    $ShowArchiveProgress = $false
}

try {
    Invoke-ArchiveDownload `
        -Uri $Url `
        -OutFile (Join-Path $TmpDir $Archive) `
        -ArchiveName $Archive `
        -ShowProgress:$ShowArchiveProgress
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
# ships no projection client, so this is normally absent.
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

if (Test-KinTruthy $env:KIN_NO_SETUP) {
    Write-Host ""
    Write-Info "Skipping repository-free setup diagnostics (KIN_NO_SETUP=1)."
} else {
    Write-Host ""
    Write-Info "Not running repository setup: MCP and review workflows are not yet covered on native Windows."
    Write-Info "Run 'kin init' in a Git repository to publish graph authority; use WSL2 for MCP, review, and projection workflows."
}

# ── Cleanup ─────────────────────────────────────────────────────────────

} finally {
    # `finally` runs for success, terminating errors, and every `exit` above.
    # Cleanup remains best-effort so a filesystem cleanup error cannot replace
    # the installer failure that the caller actually needs to diagnose.
    Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Ok "Done! Restart your terminal to use repository-free CLI diagnostics."
Write-Host "  Use WSL2 for Kin repository workflows: https://github.com/firelock-ai/kin/blob/main/docs/windows-wsl2.md" -ForegroundColor Yellow
Write-Host ""
