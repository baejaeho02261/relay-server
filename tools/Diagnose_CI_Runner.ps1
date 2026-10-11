# Standalone runner diagnosis. It does not create approval or CI evidence.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$diagnosticId = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$diagnosticLog = Join-Path $PSScriptRoot ('ci-runner-diagnostic-' + $diagnosticId + '.log')
$childLog = Join-Path $PSScriptRoot ('ci-runner-diagnostic-' + $diagnosticId + '-child.log')
$utf8 = [Text.UTF8Encoding]::new($false)
$diagnosticFile = [IO.File]::Open($diagnosticLog,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
$diagnosticFile.Dispose()
$stage = 'requirements'
$diagnosticExit = 1
$privateTemp = $null
$privateCreated = $false
$job = $null

function Write-Diagnostic([string]$Text) {
    Write-Host $Text
    [IO.File]::AppendAllText($diagnosticLog,$Text + [Environment]::NewLine,$utf8)
}

function Write-DiagnosticException([Exception]$Exception) {
    $current = $Exception
    for ($depth = 0; $null -ne $current -and $depth -lt 8; $depth++) {
        Write-Diagnostic ('Exception[' + $depth + ']: ' + $current.GetType().FullName)
        Write-Diagnostic ('HResult[' + $depth + ']: 0x' + ('{0:X8}' -f $current.HResult))
        $codes = @([regex]::Matches([string]$current.Message,'\bCI_[A-Z][A-Z0-9_]{1,100}\b') | ForEach-Object { $_.Value } | Select-Object -Unique)
        if ($codes.Count -gt 0) {
            Write-Diagnostic ('Code[' + $depth + ']: ' + ($codes -join ', '))
        } else {
            # No environment, process arguments, key material, or stack dump.
            # This script never requests or reads signing keys.
            $message = [regex]::Replace([string]$current.Message,'[\x00-\x1f\x7f]',' ')
            if ($privateTemp) { $message = $message.Replace($privateTemp,'<diagnostic-temp>') }
            if ($message.Length -gt 600) { $message = $message.Substring(0,600) + '...' }
            Write-Diagnostic ('Message[' + $depth + ']: ' + $message)
        }
        if ($current -is [ComponentModel.Win32Exception]) {
            Write-Diagnostic ('NativeErrorCode[' + $depth + ']: ' + $current.NativeErrorCode)
        }
        $current = $current.InnerException
    }
}

try {
    Write-Diagnostic ('Diagnostic log: ' + $diagnosticLog)
    Write-Diagnostic ('Child log: ' + $childLog)
    Write-Diagnostic 'This is runner diagnosis only. No approval or CI evidence is created.'
    Write-Diagnostic ('PowerShell: ' + $PSVersionTable.PSVersion + '; process bits: ' + ([IntPtr]::Size * 8))
    if ($PSVersionTable.PSVersion.Major -lt 7 -or [IntPtr]::Size -ne 8 -or -not $IsWindows) {
        throw 'CI_WINDOWS_POWERSHELL7_X64_REQUIRED'
    }
    $ciDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\ci'))
    $commonScript = Join-Path $ciDirectory 'CiCommon.ps1'
    $selfTestScript = Join-Path $ciDirectory 'Test-WindowsRunner.ps1'
    foreach ($file in @($commonScript,$selfTestScript,(Join-Path $ciDirectory 'WindowsJob.cs'))) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'CI_DIAGNOSTIC_SOURCE_MISSING' }
    }
    $sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $stage = 'load-common'
    Write-Diagnostic ('STAGE ' + $stage)
    . $commonScript

    $stage = 'private-directory'
    Write-Diagnostic ('STAGE ' + $stage)
    $privateTemp = Join-Path ([IO.Path]::GetTempPath()) ('GameCiDiagnostic-' + [Guid]::NewGuid().ToString('N'))
    New-CiPrivateDirectory $privateTemp
    $privateCreated = $true

    $stage = 'environment'
    Write-Diagnostic ('STAGE ' + $stage)
    $childEnvironment = Get-CiEnvironment $privateTemp
    Write-Diagnostic ('Environment object type: ' + $childEnvironment.GetType().FullName)

    $stage = 'launch'
    Write-Diagnostic ('STAGE ' + $stage)
    $executable = Join-Path $PSHOME 'pwsh.exe'
    $childArguments = [string[]]@('-NoLogo','-NoProfile','-NonInteractive','-File',$selfTestScript,'-PrivateRoot',$privateTemp)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $job = [GameCi.WindowsJob]::Start($executable,$childArguments,$sourceRoot,$childEnvironment,$childLog)

    $stage = 'wait'
    Write-Diagnostic ('STAGE ' + $stage)
    while (-not $job.HasExited) {
        if ($watch.Elapsed.TotalSeconds -gt 120) { throw 'CI_STAGE_TIMEOUT' }
        if ((Get-Item -LiteralPath $childLog).Length -gt 64MB) { throw 'CI_LOG_LIMIT' }
        Start-Sleep -Milliseconds 100
    }

    $stage = 'read-exit'
    Write-Diagnostic ('STAGE ' + $stage)
    $childExit = [int64]$job.ExitCode
    Write-Diagnostic ('Self-test process exit code: ' + $childExit)
    if ($childExit -ne 0) { throw 'CI_STAGE_NONZERO_EXIT' }
    $drain = [Diagnostics.Stopwatch]::StartNew()
    while (@($job.ProcessIds()).Count -ne 0 -and $drain.Elapsed.TotalSeconds -lt 2) {
        Start-Sleep -Milliseconds 50
    }
    if (@($job.ProcessIds()).Count -ne 0) { throw 'CI_STAGE_ORPHAN_PROCESS' }
    $diagnosticExit = 0
    Write-Diagnostic 'DIAGNOSTIC_SELF_TEST_COMPLETED: runner self-test only; the full Windows CI has not been run.'
} catch {
    Write-Diagnostic ('DIAGNOSTIC_FAILED_AT: ' + $stage)
    Write-DiagnosticException $_.Exception
} finally {
    if ($null -ne $job) {
        try { $job.Dispose() }
        catch {
            $diagnosticExit = 1
            Write-Diagnostic 'DIAGNOSTIC_JOB_CLEANUP_FAILED'
            Write-DiagnosticException $_.Exception
        }
    }
    if ($privateCreated) {
        try {
            $marker = Join-Path $privateTemp 'ci-owned-marker'
            $directory = Get-Item -LiteralPath $privateTemp
            if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                -not (Test-Path -LiteralPath $marker -PathType Leaf) -or
                [IO.File]::ReadAllText($marker) -ne 'GAME_WINDOWS_CI_V1') {
                throw 'CI_DIAGNOSTIC_CLEANUP_OWNERSHIP'
            }
            Remove-Item -LiteralPath $privateTemp -Recurse -Force
        } catch {
            $diagnosticExit = 1
            Write-Diagnostic 'DIAGNOSTIC_PRIVATE_CLEANUP_FAILED'
            Write-DiagnosticException $_.Exception
        }
    }
    Write-Diagnostic ('Diagnostic exit code: ' + $diagnosticExit)
    Write-Diagnostic ('Send this diagnostic log: ' + $diagnosticLog)
    if (Test-Path -LiteralPath $childLog -PathType Leaf) {
        Write-Diagnostic ('And this child log: ' + $childLog)
    } else {
        Write-Diagnostic 'No child log was created; failure occurred before the child log opened.'
    }
}
exit $diagnosticExit
