param([Parameter(Mandatory)][string]$PrivateRoot)
. (Join-Path $PSScriptRoot 'CiCommon.ps1')
$jobs=[Collections.Generic.List[IDisposable]]::new();$count=0
function Require([bool]$Value,[string]$Code){if(-not $Value){throw $Code}}
function Wait-JobExit($Job,[int]$Seconds=10){$clock=[Diagnostics.Stopwatch]::StartNew();while(-not $Job.HasExited -and $clock.Elapsed.TotalSeconds -lt $Seconds){Start-Sleep -Milliseconds 20};Require $Job.HasExited 'CI_SELFTEST_TIMEOUT'}
try {
 foreach($file in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File){$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors);Require ($errors.Count -eq 0) 'CI_SCRIPT_PARSE_FAILED'};$count++
 $dir=Join-Path $PrivateRoot 'runner-self-test';New-CiPrivateDirectory $dir
 $environment=Get-CiEnvironment $dir;$environment['GAME_CI_TEST_SENTINEL']='expected';$exe=Join-Path $PSHOME 'pwsh.exe'
 $script=Join-Path $dir 'arguments.ps1';$json=Join-Path $dir 'arguments.json'
 [IO.File]::WriteAllText($script,'param([string]$Out,[string]$A,[string]$B,[string]$C); @{a=$A;b=$B;c=$C;sentinel=$env:GAME_CI_TEST_SENTINEL;secret=$env:GAME_CI_ATTESTATION_KEY_B64}|ConvertTo-Json|Set-Content -LiteralPath $Out;exit 0')
 $values=@('space value','quote"slash\','trailing slash\')
 $job=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-File',$script,$json)+$values,$dir,$environment,(Join-Path $dir 'arguments.log'));$jobs.Add($job);Wait-JobExit $job
 Require ($job.ExitCode -eq 0) 'CI_SELFTEST_ZERO_EXIT';$observed=Read-CiJson $json
 Require ($observed.a -eq $values[0] -and $observed.b -eq $values[1] -and $observed.c -eq $values[2]) 'CI_ARGUMENT_QUOTING_FAILED';$count++
 Require ($observed.sentinel -eq 'expected' -and -not $observed.secret) 'CI_ENV_ISOLATION_FAILED';$count++
 $job=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-Command','exit 7'),$dir,$environment,(Join-Path $dir 'nonzero.log'));$jobs.Add($job);Wait-JobExit $job
 Require ($job.ExitCode -eq 7) 'CI_SELFTEST_NONZERO_EXIT';$count++
 # A real child descendant is created inside the owned job, then job disposal
 # must remove both. No process selected outside the job is ever terminated.
 $script=Join-Path $dir 'descendant.ps1';$pidFile=Join-Path $dir 'child.json'
 [IO.File]::WriteAllText($script,'param([string]$Out);$p=Start-Process -FilePath (Join-Path $PSHOME "pwsh.exe") -ArgumentList @("-NoProfile","-Command","Start-Sleep -Seconds 60") -PassThru;@{pid=$p.Id}|ConvertTo-Json|Set-Content -LiteralPath $Out;Start-Sleep -Seconds 60')
 $job=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-File',$script,$pidFile),$dir,$environment,(Join-Path $dir 'descendant.log'));$jobs.Add($job)
 $clock=[Diagnostics.Stopwatch]::StartNew();while(-not(Test-Path -LiteralPath $pidFile) -and $clock.Elapsed.TotalSeconds -lt 10){Start-Sleep -Milliseconds 50}
 Require (Test-Path -LiteralPath $pidFile) 'CI_CHILD_NOT_STARTED';$childId=[int](Read-CiJson $pidFile).pid
 Require (@($job.ProcessIds()) -contains $childId) 'CI_CHILD_NOT_OWNED';$count++
 $child=[Diagnostics.Process]::GetProcessById($childId);$null=$child.Handle;$parent=[Diagnostics.Process]::GetProcessById([int]$job.RootId);$null=$parent.Handle
 try {$job.Dispose();Require ($child.WaitForExit(5000) -and $parent.WaitForExit(5000)) 'CI_JOB_DISPOSAL_FAILED';Require ($child.ExitCode -ne 0 -and $parent.ExitCode -ne 0) 'CI_TERMINATION_EXIT_CODE';$count++}finally{$child.Dispose();$parent.Dispose()}
 Write-Output "CI_RUNNER_SELFTEST_PASS $count (Windows process tests executed)";exit 0
} catch {Write-Error 'CI_RUNNER_SELFTEST_FAILED';exit 1}finally{$cleanupError=$false;foreach($job in $jobs){try{$job.Dispose()}catch{$cleanupError=$true}};if($cleanupError){throw 'CI_SELFTEST_CLEANUP_FAILED'}}
