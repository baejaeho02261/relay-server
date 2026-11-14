# Windows PowerShell 5.1. Builds outputs but never executes the produced EXEs.
# Run from the RAD Studio command prompt, or provide actual BDS/MSBuild paths.
[CmdletBinding()]
param(
    [string]$BdsPath = $env:BDS,
    [string]$MsBuildPath,
    [string]$LogDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$nativeRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$results = New-Object 'System.Collections.Generic.List[object]'
$report = [ordered]@{
    version = 1
    kind = 'ACTUAL_LOCAL_WINDOWS_BUILD_DIAGNOSTICS'
    startedAtUtc = [DateTime]::UtcNow.ToString('o')
    finishedAtUtc = $null
    status = 'FAIL'
    compilerAuthenticity = 'NOT_ATTESTED'
    commandLineCompilerSupport = 'NOT_CHECKED'
    nativeExecutablesRun = $false
    approvalsModified = $false
    msbuild = $null
    bds = $null
    builds = @()
    error = $null
}
$runDirectory = $null
$reportFile = $null
$overallExit = 1
function Fail([string]$Code) { throw $Code }
function Assert-NoReparse([string]$Name) {
    $cursor = [IO.Path]::GetFullPath($Name)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $entry = Get-Item -LiteralPath $cursor -Force
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail 'COZY_BUILD_PATH_REPARSE_FORBIDDEN' }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
    }
}
function Require-File([string]$Name) {
    Assert-NoReparse $Name
    if (-not (Test-Path -LiteralPath $Name -PathType Leaf)) { Fail 'COZY_REQUIRED_BUILD_FILE_MISSING' }
    return [IO.Path]::GetFullPath($Name)
}
function Assert-Pe64([string]$Name) {
    $stream = [IO.File]::Open($Name, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = New-Object IO.BinaryReader($stream)
    try {
        if ($stream.Length -lt 256 -or $stream.Length -gt 67108864) { Fail 'COZY_OUTPUT_NOT_PE64' }
        if ($reader.ReadUInt16() -ne 0x5A4D) { Fail 'COZY_OUTPUT_NOT_PE64' }
        $stream.Position = 60
        $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt 1048576 -or $offset -gt ($stream.Length - 26)) { Fail 'COZY_OUTPUT_NOT_PE64' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550 -or $reader.ReadUInt16() -ne 0x8664) { Fail 'COZY_OUTPUT_NOT_PE64' }
        $stream.Position = $offset + 24
        if ($reader.ReadUInt16() -ne 0x020B) { Fail 'COZY_OUTPUT_NOT_PE64' }
    } finally { $reader.Dispose(); $stream.Dispose() }
}
try {
    if ($env:OS -ne 'Windows_NT') { Fail 'COZY_WINDOWS_HOST_REQUIRED' }
    Assert-NoReparse $nativeRoot
    if (-not $LogDirectory) {
        $LogDirectory = Join-Path ([IO.Path]::GetTempPath()) ('Cozy-Native-Build-Check-' + [Guid]::NewGuid().ToString('N'))
    }
    if (-not [IO.Path]::IsPathRooted($LogDirectory)) { Fail 'COZY_ABSOLUTE_LOG_DIRECTORY_REQUIRED' }
    $runDirectory = [IO.Path]::GetFullPath($LogDirectory).TrimEnd([char[]]@('\', '/'))
    if ($runDirectory.Equals($nativeRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $runDirectory.StartsWith($nativeRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        Fail 'COZY_LOG_DIRECTORY_MUST_BE_OUTSIDE_NATIVE_SOURCE'
    }
    Assert-NoReparse $runDirectory
    if (Test-Path -LiteralPath $runDirectory) { Fail 'COZY_LOG_DIRECTORY_MUST_BE_NEW' }
    [IO.Directory]::CreateDirectory($runDirectory) | Out-Null
    $reportFile = Join-Path $runDirectory 'Cozy.Build-Results.json'
    Write-Output ('Build diagnostics: ' + $runDirectory)
    if (-not $BdsPath -or -not [IO.Path]::IsPathRooted($BdsPath)) { Fail 'COZY_ACTUAL_BDS_PATH_REQUIRED' }
    $bds = [IO.Path]::GetFullPath($BdsPath).TrimEnd([char[]]@('\', '/'))
    Assert-NoReparse $bds
    $report.bds = $bds
    foreach ($file in @('dcc64.exe', 'bcc64.exe', 'brcc32.exe', 'CodeGear.Delphi.Targets', 'rsvars.bat')) {
        $null = Require-File (Join-Path $bds ('bin\' + $file))
    }
    if (-not $MsBuildPath) {
        $found = Get-Command msbuild.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $found) { Fail 'COZY_MSBUILD_EXECUTABLE_REQUIRED' }
        $MsBuildPath = $found.Source
    }
    if (-not [IO.Path]::IsPathRooted($MsBuildPath)) { Fail 'COZY_ABSOLUTE_MSBUILD_PATH_REQUIRED' }
    $msbuild = Require-File $MsBuildPath
    if ([IO.Path]::GetFileName($msbuild) -ine 'msbuild.exe') { Fail 'COZY_MSBUILD_EXECUTABLE_REQUIRED' }
    $report.msbuild = $msbuild
    $report.bds = $bds
    $projects = @('Cozy.Launcher', 'Cozy.Client', 'Cozy.Overlay')
    # Release is last so successful final outputs are the Release executables.
    :cozyBuilds foreach ($configuration in @('Debug', 'Release')) {
        foreach ($name in $projects) {
            $projectDirectory = Join-Path $nativeRoot ('Cozy.Projects\' + $name)
            Assert-NoReparse $projectDirectory
            $project = Require-File (Join-Path $projectDirectory ($name + '.dproj'))
            $output = Join-Path $projectDirectory ($name + '.exe')
            $log = Join-Path $runDirectory ($name + '-' + $configuration + '.log')
            # Normal verbosity retains the compiler command; diagnostic verbosity
            # is avoided because it can enumerate environment-derived properties.
            $arguments = @($project, '/t:Rebuild', ('/p:Config=' + $configuration), '/p:Platform=Win64', ('/p:BDS=' + $bds), '/m:1', '/nr:false', '/nologo', '/v:normal')
            $row = [ordered]@{project=$name; configuration=$configuration; status='FAIL'; command=@($msbuild)+$arguments; exitCode=$null; log=$log; firstCompilerDiagnostic=$null; firstPrimaryCompilerDiagnostic=$null; output=$output; outputSha512=$null; outputBytes=$null; error=$null; commandLineCompilerSupport='NOT_CHECKED'}
            $writer = $null
            try {
                # Fresh-output control: remove only this project's known EXE.
                # Never remove a directory or a sibling project's output here.
                Assert-NoReparse $output
                if (Test-Path -LiteralPath $output) {
                    if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { Fail 'COZY_OUTPUT_PATH_NOT_A_FILE' }
                    Remove-Item -LiteralPath $output -Force
                }
                $encoding = New-Object Text.UTF8Encoding($false)
                $writer = New-Object IO.StreamWriter($log, $false, $encoding)
                Write-Output ('Building ' + $name + ' ' + $configuration)
                $savedPreference = $ErrorActionPreference
                try {
                    # Native stderr is retained as log text, not discarded by
                    # Windows PowerShell's NativeCommandError handling.
                    $ErrorActionPreference = 'Continue'
                    & $msbuild @arguments 2>&1 | ForEach-Object {
                        $line = [string]$_
                        $writer.WriteLine($line)
                        Write-Output $line
                        if ($line -match '(?i)This version of the product does not support command line compiling[.]?') {
                            $row.commandLineCompilerSupport = 'UNAVAILABLE'
                            $report.commandLineCompilerSupport = 'UNAVAILABLE'
                            $row.firstPrimaryCompilerDiagnostic = [ordered]@{code='COZY_COMMAND_LINE_COMPILER_UNAVAILABLE'; line=$line}
                        }
                        if ($line -match '(?i)\b(?<code>[EF][0-9]{4})\b.*') {
                            $diagnostic = [ordered]@{code=$Matches['code'].ToUpperInvariant(); line=$line}
                            if ($null -eq $row.firstCompilerDiagnostic) { $row.firstCompilerDiagnostic = $diagnostic }
                            if ($diagnostic.code -ne 'F2063' -and $null -eq $row.firstPrimaryCompilerDiagnostic) { $row.firstPrimaryCompilerDiagnostic = $diagnostic }
                        }
                    }
                    $row.exitCode = $LASTEXITCODE
                } finally { $ErrorActionPreference = $savedPreference }
                if ($row.commandLineCompilerSupport -eq 'UNAVAILABLE') { Fail 'COZY_COMMAND_LINE_COMPILER_UNAVAILABLE' }
                if ($null -eq $row.exitCode -or $row.exitCode -ne 0) { Fail 'COZY_NATIVE_BUILD_FAILED' }
                $null = Require-File $output
                Assert-Pe64 $output
                if (-not (Test-Path -LiteralPath (Join-Path $projectDirectory 'dcu') -PathType Container)) { Fail 'COZY_DCU_DIRECTORY_MISSING' }
                Assert-NoReparse (Join-Path $projectDirectory 'dcu')
                $item = Get-Item -LiteralPath $output
                $row.outputBytes = $item.Length
                $row.outputSha512 = (Get-FileHash -LiteralPath $output -Algorithm SHA512).Hash.ToLowerInvariant()
                $row.commandLineCompilerSupport = 'AVAILABLE'
                $report.commandLineCompilerSupport = 'AVAILABLE'
                $row.status = 'PASS'
            } catch {
                $message = $_.Exception.Message
                $row.error = if ($message -cmatch '^COZY_[A-Z0-9_]+$') { $message } else { 'COZY_BUILD_CHECK_EXCEPTION' }
                if ($null -ne $writer) { $writer.WriteLine('CHECK: ' + $row.error) }
            } finally {
                if ($null -ne $writer) { $writer.Dispose() }
                $results.Add($row)
            }
            Write-Output ($row.status + ': ' + $name + ' ' + $configuration)
            if ($null -ne $row.firstPrimaryCompilerDiagnostic) {
                Write-Output ('First primary diagnostic: ' + $row.firstPrimaryCompilerDiagnostic.line)
            } elseif ($null -ne $row.firstCompilerDiagnostic) {
                Write-Output ('First compiler diagnostic (dependency wrapper): ' + $row.firstCompilerDiagnostic.line)
            }
            if ($row.commandLineCompilerSupport -eq 'UNAVAILABLE') {
                $report.error = 'COZY_COMMAND_LINE_COMPILER_UNAVAILABLE'
                Write-Output 'The selected compiler refused command-line compilation. Check the installed compiler and license; use the IDE when your edition supports it.'
                break cozyBuilds
            }
        }
    }
    if ($results.Count -eq 6 -and @($results | Where-Object { $_.status -ne 'PASS' }).Count -eq 0) {
        $report.status = 'PASS'
        $overallExit = 0
    }
} catch {
    $message = $_.Exception.Message
    $report.error = if ($message -cmatch '^COZY_[A-Z0-9_]+$') { $message } else { 'COZY_BUILD_CHECK_EXCEPTION' }
    Write-Error -Message $report.error -ErrorAction Continue
} finally {
    $report.finishedAtUtc = [DateTime]::UtcNow.ToString('o')
    $report.builds = @($results.ToArray())
    if ($null -ne $reportFile) {
        $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportFile -Encoding UTF8
        Write-Output ('Result: ' + $reportFile)
    }
}
Write-Output ('Build result: ' + $report.status + '; produced EXEs were not executed; compiler authenticity is not attested.')
exit $overallExit
