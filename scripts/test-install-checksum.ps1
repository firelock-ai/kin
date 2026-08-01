# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallerPath = Join-Path $ScriptsDir "install.ps1"
$FixturesPath = Join-Path $ScriptsDir "install-checksum-fixtures.json"

$Tokens = $null
$ParseErrors = $null
$InstallerAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $InstallerPath,
    [ref]$Tokens,
    [ref]$ParseErrors
)
if (@($ParseErrors).Count -gt 0) {
    $Messages = @($ParseErrors | ForEach-Object { $_.Message }) -join "; "
    throw "install.ps1 failed PowerShell parsing: $Messages"
}

function Get-InstallerFunction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $FunctionAst = @($InstallerAst.FindAll(
        {
            param($Node)
            $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        },
        $true
    )) | Where-Object { $_.Name -ceq $Name } | Select-Object -First 1
    if ($null -eq $FunctionAst) {
        throw "$Name was not found in install.ps1"
    }
    return [ScriptBlock]::Create($FunctionAst.Extent.Text)
}

. (Get-InstallerFunction "Resolve-ArchiveChecksum")
. (Get-InstallerFunction "Format-ByteCount")
. (Get-InstallerFunction "Invoke-ArchiveDownload")

if ((Format-ByteCount 1536) -cne "1.5 KiB") {
    throw "Format-ByteCount did not produce invariant binary units"
}

# Exercise the archive stream/copy loop without network or progress-host
# coupling. The production HTTP path feeds the same stream loop after reading
# only response headers, while checksum parsing remains an independent fetch.
$ProgressFixtureDir = Join-Path ([System.IO.Path]::GetTempPath()) "kin-progress-test-$(Get-Random)"
New-Item -ItemType Directory -Path $ProgressFixtureDir -Force | Out-Null
try {
    $ProgressSource = Join-Path $ProgressFixtureDir "source.zip"
    $ProgressDestination = Join-Path $ProgressFixtureDir "destination.zip"
    $ProgressBytes = [byte[]]::new((2 * 1024 * 1024) + 17)
    [System.IO.File]::WriteAllBytes($ProgressSource, $ProgressBytes)
    Invoke-ArchiveDownload `
        -Uri $ProgressSource `
        -OutFile $ProgressDestination `
        -ArchiveName "kin-test.zip"

    $SourceHash = (Get-FileHash -Path $ProgressSource -Algorithm SHA256).Hash
    $DestinationHash = (Get-FileHash -Path $ProgressDestination -Algorithm SHA256).Hash
    if ($SourceHash -cne $DestinationHash) {
        throw "Invoke-ArchiveDownload changed archive bytes"
    }
} finally {
    Remove-Item -LiteralPath $ProgressFixtureDir -Recurse -Force
}

$Fixtures = Get-Content $FixturesPath -Raw | ConvertFrom-Json
$Passed = 0

foreach ($Case in $Fixtures.cases) {
    $Actual = $null
    $Failure = $null
    try {
        $Actual = Resolve-ArchiveChecksum `
            -ChecksumContent ([string]$Case.content) `
            -ArchiveName ([string]$Case.archive)
    } catch {
        $Failure = $_.Exception.Message
    }

    $ErrorProperty = $Case.PSObject.Properties["error_contains"]
    if ($null -ne $ErrorProperty) {
        $ExpectedError = [string]$ErrorProperty.Value
        if ($null -eq $Failure) {
            throw "$($Case.name): expected failure containing '$ExpectedError', got success '$Actual'"
        }
        if (-not $Failure.Contains($ExpectedError)) {
            throw "$($Case.name): expected failure containing '$ExpectedError', got '$Failure'"
        }
    } else {
        $Expected = [string]$Case.expected
        if ($null -ne $Failure) {
            throw "$($Case.name): unexpected failure '$Failure'"
        }
        if ($Actual -cne $Expected) {
            throw "$($Case.name): expected '$Expected', got '$Actual'"
        }
    }

    $Passed++
    Write-Host "PASS: $($Case.name)"
}

Write-Host "$Passed checksum fixture cases passed"
