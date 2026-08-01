# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ScriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallerPath = Join-Path $ScriptsDir "install.ps1"
$FixturesPath = Join-Path $ScriptsDir "install-checksum-fixtures.json"
$WindowsContractPath = Join-Path $ScriptsDir "assert-windows-init-contract.sh"

function Assert-InstallerEmitsSupportWarning {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InstallerSource,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedNotice
    )

    # Execute the real installer prefix in a child of the engine under test.
    # The sentinel is inserted after the warning and before any version lookup,
    # filesystem mutation, or network request. This proves the user sees the
    # warning at runtime without turning a unit test into an installer smoke.
    $StopStatement = '$PreviousVersion = $null'
    $StopCount = ([regex]::Matches(
        $InstallerSource,
        [regex]::Escape($StopStatement)
    )).Count
    if ($StopCount -ne 1) {
        throw "install.ps1 must contain one pre-download warning-probe boundary; found $StopCount"
    }
    $ProbeSource = $InstallerSource.Replace(
        $StopStatement,
        "exit 86`n`n$StopStatement"
    )
    $ProbePath = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) "kin-installer-warning-$PID-$([guid]::NewGuid().ToString('N')).ps1"
    $PowerShellExecutable = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($PowerShellExecutable) -or -not (Test-Path $PowerShellExecutable)) {
        throw "could not resolve the current PowerShell executable"
    }

    $PreviousArchitecture = $env:PROCESSOR_ARCHITECTURE
    try {
        [System.IO.File]::WriteAllText(
            $ProbePath,
            $ProbeSource,
            (New-Object System.Text.UTF8Encoding -ArgumentList $false)
        )
        $env:PROCESSOR_ARCHITECTURE = "AMD64"
        $Output = @(
            & $PowerShellExecutable `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $ProbePath 2>&1
        )
        $ExitCode = $LASTEXITCODE
    } finally {
        if ($null -eq $PreviousArchitecture) {
            Remove-Item Env:PROCESSOR_ARCHITECTURE -ErrorAction SilentlyContinue
        } else {
            $env:PROCESSOR_ARCHITECTURE = $PreviousArchitecture
        }
        Remove-Item -Path $ProbePath -Force -ErrorAction SilentlyContinue
    }

    $OutputText = $Output | Out-String
    if ($ExitCode -ne 86) {
        throw "installer warning probe exited $ExitCode instead of 86:`n$OutputText"
    }
    $ExpectedOutput = "! $ExpectedNotice"
    if (-not $OutputText.Contains($ExpectedOutput)) {
        throw "installer did not emit the native-Windows support warning before download:`n$OutputText"
    }
}

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

$InstallerSource = Get-Content $InstallerPath -Raw -Encoding UTF8
$WindowsContract = Get-Content $WindowsContractPath -Raw -Encoding UTF8
$NoticeMatches = [regex]::Matches(
    $WindowsContract,
    '(?m)^PUBLIC_SUPPORT_NOTICE="([^"]+)"$'
)
if ($NoticeMatches.Count -ne 1) {
    throw "Windows admission contract must bind PUBLIC_SUPPORT_NOTICE exactly once; found $($NoticeMatches.Count)"
}
$ExpectedNotice = $NoticeMatches[0].Groups[1].Value
Assert-InstallerEmitsSupportWarning `
    -InstallerSource $InstallerSource `
    -ExpectedNotice $ExpectedNotice
Write-Host "PASS: native-Windows installer emits its support warning before download"

# Prove the runtime assertion is load-bearing. A token-based guard sees the
# statement inside this branch; executing the prefix must still reject it.
$WarningStatement = 'Write-Host "  ! $NativeWindowsSupportNotice" -ForegroundColor Yellow'
$FalseBranchWarning = @'
if ($false) {
    Write-Host "  ! $NativeWindowsSupportNotice" -ForegroundColor Yellow
}
'@
$FalseBranchInstaller = $InstallerSource.Replace(
    $WarningStatement,
    $FalseBranchWarning
)
if ($FalseBranchInstaller -ceq $InstallerSource) {
    throw "could not construct the false-branch warning mutation"
}
$FalseBranchFailure = $null
try {
    Assert-InstallerEmitsSupportWarning `
        -InstallerSource $FalseBranchInstaller `
        -ExpectedNotice $ExpectedNotice
} catch {
    $FalseBranchFailure = $_.Exception.Message
}
if ($null -eq $FalseBranchFailure) {
    throw 'if ($false) around the native-Windows warning escaped the runtime assertion'
}
if (-not $FalseBranchFailure.Contains("did not emit the native-Windows support warning")) {
    throw "false-branch warning mutation failed for the wrong reason: $FalseBranchFailure"
}
Write-Host 'PASS: if ($false) cannot disable the native-Windows support warning'

Write-Host "$Passed checksum fixture cases, the Windows target contract, and runtime warning proof passed"
