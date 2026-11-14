param([string]$ResultsDirectory = $PSScriptRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$reportPath = $null
$run = $null
$stages = @()
$exitCode = 1
function Write-ResultJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
function File-Binding([string]$Path) {
    return @{path = [IO.Path]::GetFullPath($Path); sha512 = (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash.ToLowerInvariant()}
}
function Invoke-Tool([string]$Executable, [string[]]$Arguments, [string]$Name, [int]$Seconds = 90) {
    # No shell; one resolved executable and an argument array. ArgumentList avoids
    # the historical PowerShell array-to-string/combined-executable-path failure.
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Executable
    $start.WorkingDirectory = $run
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # PowerShell variables are case-insensitive: do not overwrite the stage $Name.
    foreach ($environmentName in @('CL','_CL_','LINK','_LINK_')) { $start.Environment.Remove($environmentName) | Out-Null }
    foreach ($argument in $Arguments) { $start.ArgumentList.Add([string]$argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'CFG_TOOL_START_FAILED' }
        $outRead = $process.StandardOutput.ReadToEndAsync()
        $errRead = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Seconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'CFG_TOOL_TIMEOUT'
        }
        $stdout = $outRead.GetAwaiter().GetResult()
        $stderr = $errRead.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $run ($Name + '.stdout.log')), $stdout, [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText((Join-Path $run ($Name + '.stderr.log')), $stderr, [Text.UTF8Encoding]::new($false))
        return @{id = $Name; exitCode = $process.ExitCode; stdout = $stdout; stderr = $stderr}
    } finally { $process.Dispose() }
}
try {
    if ($PSVersionTable.PSVersion.Major -lt 7 -or -not $IsWindows -or [IntPtr]::Size -ne 8) {
        throw 'CFG_WINDOWS_POWERSHELL7_X64_REQUIRED'
    }
    $ResultsDirectory = [IO.Path]::GetFullPath($ResultsDirectory)
    [IO.Directory]::CreateDirectory($ResultsDirectory) | Out-Null
    $id = 'cfg-enforcement-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $run = Join-Path $ResultsDirectory $id
    [IO.Directory]::CreateDirectory($run) | Out-Null
    $reportPath = Join-Path $ResultsDirectory ($id + '.json')
    $cl = [string](Get-Command -Name cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $cl = [IO.Path]::GetFullPath($cl)
    # Use this compiler's sibling linker, not an unrelated link.exe from PATH.
    $link = Join-Path ([IO.Path]::GetDirectoryName($cl)) 'link.exe'
    if (-not (Test-Path -LiteralPath $link -PathType Leaf)) { throw 'CFG_MSVC_LINKER_MISSING' }
    $node = [string](Get-Command -Name node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\Railway\Cozy.Tests\Cozy.Security\Cozy.CfgEnforcementProbe.cpp'))
    $validator = Join-Path $PSScriptRoot 'peace.cfg-enforcement-report.js'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
        -not (Test-Path -LiteralPath $validator -PathType Leaf)) { throw 'CFG_SOURCE_PACKAGE_INCOMPLETE' }
    $sourcePin = File-Binding $source
    $compilerPin = File-Binding $cl
    $linkerPin = File-Binding $link
    $compiledSource = Join-Path $run 'Cozy.CfgEnforcementProbe.cpp'
    [IO.File]::Copy($source, $compiledSource, $false)
    if ((File-Binding $compiledSource).sha512 -cne $sourcePin.sha512) { throw 'CFG_SOURCE_COPY_CHANGED' }
    Write-Host 'Standalone MSVC/Windows CFG test; A/B/O and server policy are not changed.'
    Write-Host ('Run folder: ' + $run)
    $guarded = Join-Path $run 'CfgEnforcementGuarded.exe'
    $control = Join-Path $run 'CfgEnforcementControl.exe'
    $common = @('/nologo','/c','/O2','/GS','/sdl','/W4','/WX','/MT','/EHsc','/utf-8','/Bv')
    foreach ($variant in @('guarded','control')) {
        $isGuarded = $variant -eq 'guarded'
        $obj = Join-Path $run ($variant + '.obj')
        $exe = if ($isGuarded) { $guarded } else { $control }
        $compileArgs = $common + @(
            $(if ($isGuarded) {'/guard:cf'} else {'/guard:cf-'}),
            $(if ($isGuarded) {'/DGAME_EXPECT_CFG=1'} else {'/DGAME_EXPECT_CFG=0'}),
            ('/Fo' + $obj), $compiledSource)
        $compile = Invoke-Tool $cl $compileArgs ('compile-' + $variant)
        $stages += @{id = $compile.id; exitCode = $compile.exitCode; arguments = $compileArgs}
        if ($compile.exitCode -ne 0 -or -not (Test-Path -LiteralPath $obj -PathType Leaf)) {
            throw ('CFG_COMPILE_FAILED_' + $variant.ToUpperInvariant())
        }
        $linkArgs = @('/NOLOGO','/WX','/MACHINE:X64','/INCREMENTAL:NO','/DYNAMICBASE','/HIGHENTROPYVA',
            '/NXCOMPAT','/SUBSYSTEM:CONSOLE',
            $(if ($isGuarded) {'/GUARD:CF'} else {'/GUARD:NO'}), ('/OUT:' + $exe), $obj, 'kernel32.lib')
        $linked = Invoke-Tool $link $linkArgs ('link-' + $variant)
        $stages += @{id = $linked.id; exitCode = $linked.exitCode; arguments = $linkArgs}
        if ($linked.exitCode -ne 0 -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            throw ('CFG_LINK_FAILED_' + $variant.ToUpperInvariant())
        }
    }
    foreach ($pin in @($sourcePin,$compilerPin,$linkerPin)) {
        if ((File-Binding $pin.path).sha512 -cne $pin.sha512) { throw 'CFG_BUILD_INPUT_CHANGED' }
    }
    $guardedPin = File-Binding $guarded
    $controlPin = File-Binding $control
    $native = Invoke-Tool $guarded @('--control', $control) 'native-probe' 60
    $nativeReport = $native.stdout | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    $report = @{
        version = 1; kind = 'CFG_RUNTIME_ENFORCEMENT'; outcome = 'PASS'; windowsExecuted = $true
        scope = 'MSVC_PROBE_ONLY'; productionCfgCoverage = $false;        publicationApproval = $false; stages = $stages; nativeReport = $nativeReport
        nativeExitCode = $native.exitCode; finishedAt = [DateTime]::UtcNow.ToString('o')
        environment = @{os = [Environment]::OSVersion.VersionString; processBits = 64
            powershell = $PSVersionTable.PSVersion.ToString(); windowsSdk = $env:WindowsSDKVersion
            windowsSdkDirectory = $env:WindowsSdkDir
            compilerVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($cl).FileVersion
            linkerVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($link).FileVersion}
        bindings = @{source = $sourcePin; compiler = $compilerPin; linker = $linkerPin
            guardedProbe = $guardedPin; unguardedProbe = $controlPin}
        documentation = @(
            'https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard',
            'https://learn.microsoft.com/en-us/windows/win32/secbp/control-flow-guard',
            'https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail')
    }
    # The candidate PASS is not exposed as the result until independent policy
    # validation succeeds. Failure overwrites the candidate as FAIL.
    $candidate = Join-Path $run 'candidate-report.json'
    Write-ResultJson $candidate $report
    $validation = Invoke-Tool $node @($validator, $candidate) 'validate-report'
    if ($validation.exitCode -ne 0) { throw 'CFG_RESULT_VALIDATION_FAILED' }
    Write-ResultJson $reportPath $report
    Write-Host 'PASS: exact CFG failfast and both controls observed. Scope: this MSVC probe only.'
    $exitCode = 0
} catch {
    $message = $_.Exception.Message
    $errorCode = if ($message -cmatch '^CFG_[A-Z0-9_]+$') {$message} else {'CFG_RUNNER_FAILED'}
    Write-Host ('ERROR: ' + $errorCode)
    Write-Host $message
    if ($reportPath) {
        Write-ResultJson $reportPath @{version=1; kind='CFG_RUNTIME_ENFORCEMENT'; outcome='FAIL'
            windowsExecuted=($stages.Count -gt 0); productionCfgCoverage=$false;            publicationApproval=$false; error=$errorCode; detail=$message; stages=$stages
            finishedAt=[DateTime]::UtcNow.ToString('o')}
    }
} finally {
    if ($reportPath) { Write-Host ('Result: ' + $reportPath) }
    if ($run) { Write-Host ('Logs and isolated probes: ' + $run) }
}
exit $exitCode
