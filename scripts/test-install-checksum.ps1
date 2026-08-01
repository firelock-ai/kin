# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# The harness intentionally launches child PowerShell processes that must fail.
# Own the native-exit status explicitly so a successful test run cannot leak a
# child's expected non-zero status back to the calling CI shell.
$global:LASTEXITCODE = 0

$ScriptsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallerPath = Join-Path $ScriptsDir "install.ps1"
$FixturesPath = Join-Path $ScriptsDir "install-checksum-fixtures.json"
$WindowsContractPath = Join-Path $ScriptsDir "assert-windows-init-contract.sh"

function Invoke-PowerShellFile {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PowerShellExecutable,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptPath
    )

    # Start-Process exposes the child's exit code on the returned Process
    # object without mutating PowerShell's session-wide $LASTEXITCODE. Redirect
    # to distinct files for compatibility with Windows PowerShell 5.1.
    $CaptureRoot = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) "kin-powershell-child-$PID-$([guid]::NewGuid().ToString('N'))"
    $StdoutPath = Join-Path $CaptureRoot "stdout.txt"
    $StderrPath = Join-Path $CaptureRoot "stderr.txt"
    New-Item -ItemType Directory -Path $CaptureRoot -Force | Out-Null
    try {
        $QuotedScriptPath = '"{0}"' -f $ScriptPath.Replace('"', '\"')
        $Child = Start-Process `
            -FilePath $PowerShellExecutable `
            -ArgumentList @(
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-File", $QuotedScriptPath
            ) `
            -NoNewWindow `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $StdoutPath `
            -RedirectStandardError $StderrPath

        $OutputParts = @()
        if (Test-Path -LiteralPath $StdoutPath) {
            $OutputParts += Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $StderrPath) {
            $OutputParts += Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue
        }
        return [pscustomobject]@{
            ExitCode = [int]$Child.ExitCode
            Output = ($OutputParts -join [Environment]::NewLine)
        }
    } finally {
        Remove-Item -LiteralPath $CaptureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

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
        $ProbeResult = Invoke-PowerShellFile `
            -PowerShellExecutable $PowerShellExecutable `
            -ScriptPath $ProbePath
        $OutputText = [string]$ProbeResult.Output
        $ExitCode = [int]$ProbeResult.ExitCode
    } finally {
        if ($null -eq $PreviousArchitecture) {
            Remove-Item Env:PROCESSOR_ARCHITECTURE -ErrorAction SilentlyContinue
        } else {
            $env:PROCESSOR_ARCHITECTURE = $PreviousArchitecture
        }
        Remove-Item -Path $ProbePath -Force -ErrorAction SilentlyContinue
    }

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

function Get-InstallerFunction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $FunctionAst = $null
    foreach ($Candidate in $InstallerAst.EndBlock.Statements) {
        if (
            $Candidate -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Candidate.Name -ceq $Name
        ) {
            $FunctionAst = $Candidate
            break
        }
    }
    if ($null -eq $FunctionAst) {
        throw "$Name was not found in install.ps1"
    }
    return [ScriptBlock]::Create($FunctionAst.Extent.Text)
}

. (Get-InstallerFunction "Resolve-ArchiveChecksum")
. (Get-InstallerFunction "Resolve-KinWindowsArchiveArchitecture")
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

function Test-FailedInstallerRemovesArchive {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("checksum", "extraction")]
        [string]$FailureMode
    )

    $FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "kin-installer-cleanup-test-$(Get-Random)"
    $FailureTempRoot = Join-Path $FixtureRoot "failure-temp"
    $ReadyPath = Join-Path $FixtureRoot "server-port"
    $KinHome = Join-Path $FixtureRoot "kin-home"
    $ArchiveLength = (2 * 1024 * 1024) + 17
    $ServerJob = $null
    $ChecksumText = $null

    if ($FailureMode -eq "extraction") {
        $Hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $ArchiveHash = [BitConverter]::ToString(
                $Hasher.ComputeHash([byte[]]::new($ArchiveLength))
            ).Replace("-", "").ToLowerInvariant()
            $ChecksumText = "$ArchiveHash  kin-windows-x86_64.zip`n"
        } finally {
            $Hasher.Dispose()
        }
    }

    New-Item -ItemType Directory -Path $FailureTempRoot -Force | Out-Null

    $EnvironmentNames = @(
        "TEMP",
        "TMP",
        "KIN_HOME",
        "KIN_DIR",
        "KIN_VERSION",
        "KIN_BASE_URL",
        "KIN_NO_SETUP",
        "PROCESSOR_ARCHITECTURE"
    )
    $SavedEnvironment = @{}
    foreach ($Name in $EnvironmentNames) {
        $SavedEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, "Process")
    }

    try {
        # Serve a complete multi-megabyte archive followed by either a checksum
        # 404 or its valid digest over intentionally invalid ZIP bytes. The two
        # cases cover both an explicit `exit` and an unhandled terminating error.
        $ServerJob = Start-Job -ArgumentList $ReadyPath, $ArchiveLength, $ChecksumText -ScriptBlock {
            param($ReadyPath, $ArchiveLength, $ChecksumText)

            $ErrorActionPreference = "Stop"
            $Listener = [System.Net.Sockets.TcpListener]::new(
                [System.Net.IPAddress]::Loopback,
                0
            )
            try {
                $Listener.Start()
                $Port = ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port
                [System.IO.File]::WriteAllText($ReadyPath, [string]$Port)

                for ($RequestIndex = 0; $RequestIndex -lt 2; $RequestIndex++) {
                    $Client = $Listener.AcceptTcpClient()
                    try {
                        $Stream = $Client.GetStream()
                        $Reader = [System.IO.StreamReader]::new(
                            $Stream,
                            [System.Text.Encoding]::ASCII,
                            $false,
                            1024,
                            $true
                        )
                        try {
                            $RequestLine = $Reader.ReadLine()
                            while (-not [string]::IsNullOrEmpty($Reader.ReadLine())) { }
                        } finally {
                            $Reader.Dispose()
                        }

                        if ($RequestLine -match '\.sha256(?:\s|\?)') {
                            if ($null -eq $ChecksumText) {
                                $Header = "HTTP/1.1 404 Not Found`r`nContent-Length: 0`r`nConnection: close`r`n`r`n"
                                $HeaderBytes = [System.Text.Encoding]::ASCII.GetBytes($Header)
                                $Stream.Write($HeaderBytes, 0, $HeaderBytes.Length)
                            } else {
                                $ChecksumBytes = [System.Text.Encoding]::ASCII.GetBytes($ChecksumText)
                                $Header = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: $($ChecksumBytes.Length)`r`nConnection: close`r`n`r`n"
                                $HeaderBytes = [System.Text.Encoding]::ASCII.GetBytes($Header)
                                $Stream.Write($HeaderBytes, 0, $HeaderBytes.Length)
                                $Stream.Write($ChecksumBytes, 0, $ChecksumBytes.Length)
                            }
                        } else {
                            $Header = "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Length: $ArchiveLength`r`nConnection: close`r`n`r`n"
                            $HeaderBytes = [System.Text.Encoding]::ASCII.GetBytes($Header)
                            $Stream.Write($HeaderBytes, 0, $HeaderBytes.Length)

                            $Buffer = [byte[]]::new(64 * 1024)
                            [long]$Remaining = $ArchiveLength
                            while ($Remaining -gt 0) {
                                $Count = [int][Math]::Min($Buffer.Length, $Remaining)
                                $Stream.Write($Buffer, 0, $Count)
                                $Remaining -= $Count
                            }
                        }
                        $Stream.Flush()
                    } finally {
                        $Client.Dispose()
                    }
                }
            } finally {
                $Listener.Stop()
            }
        }

        $ReadyDeadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not (Test-Path -LiteralPath $ReadyPath)) {
            if ($ServerJob.State -eq "Failed") {
                $ServerFailure = Receive-Job -Job $ServerJob 2>&1 | Out-String
                throw "installer fixture server failed before readiness: $ServerFailure"
            }
            if ([DateTime]::UtcNow -ge $ReadyDeadline) {
                throw "installer fixture server did not become ready"
            }
            Start-Sleep -Milliseconds 50
        }
        $ServerPort = [int](Get-Content -LiteralPath $ReadyPath -Raw)

        [Environment]::SetEnvironmentVariable("TEMP", $FailureTempRoot, "Process")
        [Environment]::SetEnvironmentVariable("TMP", $FailureTempRoot, "Process")
        [Environment]::SetEnvironmentVariable("KIN_HOME", $KinHome, "Process")
        [Environment]::SetEnvironmentVariable("KIN_DIR", $KinHome, "Process")
        [Environment]::SetEnvironmentVariable("KIN_VERSION", "9.9.9", "Process")
        [Environment]::SetEnvironmentVariable(
            "KIN_BASE_URL",
            "http://127.0.0.1:$ServerPort",
            "Process"
        )
        [Environment]::SetEnvironmentVariable("KIN_NO_SETUP", "1", "Process")
        [Environment]::SetEnvironmentVariable("PROCESSOR_ARCHITECTURE", "AMD64", "Process")

        $PowerShellExe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $FailureResult = Invoke-PowerShellFile `
            -PowerShellExecutable $PowerShellExe `
            -ScriptPath $InstallerPath
        $FailureOutput = [string]$FailureResult.Output
        $FailureExitCode = [int]$FailureResult.ExitCode

        if ($FailureExitCode -eq 0) {
            throw "installer unexpectedly succeeded in the $FailureMode failure fixture"
        }
        $ExpectedMarker = if ($FailureMode -eq "checksum") {
            "Could not download checksum file"
        } else {
            "Installing to"
        }
        if (-not $FailureOutput.Contains($ExpectedMarker)) {
            throw "installer did not reach the intended $FailureMode failure: $FailureOutput"
        }

        $Leaks = @(Get-ChildItem `
            -LiteralPath $FailureTempRoot `
            -Directory `
            -Filter "kin-install-*" `
            -ErrorAction SilentlyContinue)
        if ($Leaks.Count -ne 0) {
            $LeakPaths = @($Leaks | ForEach-Object { $_.FullName }) -join ", "
            throw "failed installer leaked its staged archive directory: $LeakPaths"
        }
        if (-not (Test-Path -LiteralPath $ReadyPath)) {
            throw "installer cleanup escaped its own temporary directory and removed fixture state"
        }
        Write-Host "PASS: $FailureMode failure removes its staged release archive"
    } finally {
        foreach ($Name in $EnvironmentNames) {
            [Environment]::SetEnvironmentVariable(
                $Name,
                $SavedEnvironment[$Name],
                "Process"
            )
        }
        if ($null -ne $ServerJob) {
            Stop-Job -Job $ServerJob -ErrorAction SilentlyContinue
            Remove-Job -Job $ServerJob -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $FixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Test-FailedInstallerRemovesArchive -FailureMode "checksum"
Test-FailedInstallerRemovesArchive -FailureMode "extraction"

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

if ($global:LASTEXITCODE -ne 0) {
    throw "test harness leaked native exit status $global:LASTEXITCODE after expected child failures"
}
Write-Host "PASS: expected child failures leave the harness exit status clean"
Write-Host "$Passed checksum fixture cases, the Windows target contract, and runtime warning proof passed"
exit 0
