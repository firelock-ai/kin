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

$FunctionAst = $InstallerAst.Find(
    {
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Node.Name -ceq "Resolve-ArchiveChecksum"
    },
    $true
)
if ($null -eq $FunctionAst) {
    throw "Resolve-ArchiveChecksum was not found in install.ps1"
}

$ArchitectureFunctionAst = $InstallerAst.Find(
    {
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Node.Name -ceq "Resolve-KinWindowsArchiveArchitecture"
    },
    $true
)
if ($null -eq $ArchitectureFunctionAst) {
    throw "Resolve-KinWindowsArchiveArchitecture was not found in install.ps1"
}

. ([ScriptBlock]::Create($FunctionAst.Extent.Text))
. ([ScriptBlock]::Create($ArchitectureFunctionAst.Extent.Text))
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

$ResolvedX64 = Resolve-KinWindowsArchiveArchitecture `
    -ProcessArchitecture "AMD64" `
    -Is64BitProcess $true
if ($ResolvedX64 -cne "x86_64") {
    throw "AMD64 PowerShell resolved '$ResolvedX64', expected the published x86_64 archive"
}

$Arm64Failure = $null
try {
    Resolve-KinWindowsArchiveArchitecture `
        -ProcessArchitecture "ARM64" `
        -Is64BitProcess $true | Out-Null
} catch {
    $Arm64Failure = $_.Exception.Message
}
if ($null -eq $Arm64Failure -or -not $Arm64Failure.Contains("No native Windows ARM64 archive is published")) {
    throw "native ARM64 PowerShell must fail before fabricating an archive URL; got '$Arm64Failure'"
}

$X86Failure = $null
try {
    Resolve-KinWindowsArchiveArchitecture `
        -ProcessArchitecture "x86" `
        -Is64BitProcess $false | Out-Null
} catch {
    $X86Failure = $_.Exception.Message
}
if ($null -eq $X86Failure -or -not $X86Failure.Contains("32-bit PowerShell is not supported")) {
    throw "32-bit PowerShell must fail before selecting an archive; got '$X86Failure'"
}

Write-Host "$Passed checksum fixture cases and the Windows target contract passed"
