param([Parameter(Mandatory)][string]$PrivateRoot)
. (Join-Path $PSScriptRoot 'CiCommon.ps1')
$jobs=[Collections.Generic.List[IDisposable]]::new();$count=0
function Require([bool]$Value,[string]$Code){if(-not $Value){throw $Code}}
function Wait-JobExit($Job,[int]$Seconds=10){$clock=[Diagnostics.Stopwatch]::StartNew();while(-not $Job.HasExited -and $clock.Elapsed.TotalSeconds -lt $Seconds){Start-Sleep -Milliseconds 20};Require $Job.HasExited 'CI_SELFTEST_TIMEOUT'}
try {
 foreach($file in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File){$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors);Require ($errors.Count -eq 0) 'CI_SCRIPT_PARSE_FAILED'};$count++
 $dir=Join-Path $PrivateRoot 'runner-self-test';New-CiPrivateDirectory $dir
 $environment=Get-CiEnvironment $dir;$environment['GAME_CI_TEST_SENTINEL']='expected';$exe=Join-Path $PSHOME 'pwsh.exe'
 Require ($environment -is [Collections.Generic.Dictionary[string,string]]) 'CI_ENV_TYPE_FAILED'
 Require ($environment['temp'] -eq $dir) 'CI_ENV_CASE_FAILED'
 # Command results and wrapped strings used to survive in Hashtable values and
 # fail the C# cast before CreateProcess. Exercise both through the typed map.
 $environment['GAME_CI_TEST_PATH']=Join-Path $dir 'space value'
 $wrappedText=-join @([char]0xD55C,[char]0xAE00,' space=value')
 $environment['GAME_CI_TEST_WRAPPED']=[psobject]::AsPSObject($wrappedText)
 $invalidEnvironment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
 $invalidEnvironment['BAD=NAME']='value';$invalidLog=Join-Path $dir 'invalid-environment.log';$rejected=$false
 try {$unexpected=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-Command','exit 0'),$dir,$invalidEnvironment,$invalidLog);$jobs.Add($unexpected)}
 catch {$cause=$_.Exception;while($cause.InnerException){$cause=$cause.InnerException};$rejected=$cause.Message -eq 'CI_ENV_INVALID'}
 Require ($rejected -and -not(Test-Path -LiteralPath $invalidLog)) 'CI_INVALID_ENV_NOT_REJECTED';$count++
 $script=Join-Path $dir 'arguments.ps1';$json=Join-Path $dir 'arguments.json'
 [IO.File]::WriteAllText($script,'param([string]$Out,[string]$A,[string]$B,[string]$C); @{a=$A;b=$B;c=$C;sentinel=$env:GAME_CI_TEST_SENTINEL;secret=$env:GAME_CI_ATTESTATION_KEY_B64;temp=$env:TEMP;tmp=$env:TMP;data=$env:DATA_DIR;npm=$env:NPM_CONFIG_USERCONFIG;pathValue=$env:GAME_CI_TEST_PATH;wrapped=$env:GAME_CI_TEST_WRAPPED}|ConvertTo-Json|Set-Content -LiteralPath $Out;exit 0')
 $values=@('space value','quote"slash\','trailing slash\')
 $job=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-File',$script,$json)+$values,$dir,$environment,(Join-Path $dir 'arguments.log'));$jobs.Add($job);Wait-JobExit $job
 Require ($job.ExitCode -eq 0) 'CI_SELFTEST_ZERO_EXIT';$observed=Read-CiJson $json
 Require ($observed.a -eq $values[0] -and $observed.b -eq $values[1] -and $observed.c -eq $values[2]) 'CI_ARGUMENT_QUOTING_FAILED';$count++
 Require ($observed.sentinel -eq 'expected' -and -not $observed.secret) 'CI_ENV_ISOLATION_FAILED';$count++
 Require ($observed.temp -eq $dir -and $observed.tmp -eq $dir -and $observed.data -eq $environment['DATA_DIR'] -and $observed.npm -eq $environment['NPM_CONFIG_USERCONFIG'] -and $observed.pathValue -eq $environment['GAME_CI_TEST_PATH'] -and $observed.wrapped -eq $wrappedText) 'CI_ENV_ROUNDTRIP_FAILED';$count++
 $job=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-Command','exit 7'),$dir,$environment,(Join-Path $dir 'nonzero.log'));$jobs.Add($job);Wait-JobExit $job
 Require ($job.ExitCode -eq 7) 'CI_SELFTEST_NONZERO_EXIT';$count++
 # A RAD Studio shell can expose several MSBuild executables in PATH. Resolve
 # one scalar path, preserving PATH precedence even when directories have spaces.
 $stageTokens=$null;$stageErrors=$null
 $stageAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Windows-Stage.ps1'),[ref]$stageTokens,[ref]$stageErrors)
 Require ($stageErrors.Count -eq 0) 'CI_COMMAND_RESOLUTION_SOURCE_PARSE_FAILED'
 $msbuildAssignments=@($stageAst.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.Extent.Text -eq '$msbuild'},$false))
 Require ($msbuildAssignments.Count -eq 1) 'CI_COMMAND_RESOLUTION_SOURCE_ASSIGNMENT_FAILED'
 $commandName='msbuild.exe'
 $firstCommandDirectory=Join-Path $dir 'command first';$secondCommandDirectory=Join-Path $dir 'command second'
 [IO.Directory]::CreateDirectory($firstCommandDirectory)|Out-Null;[IO.Directory]::CreateDirectory($secondCommandDirectory)|Out-Null
 $firstCommand=Join-Path $firstCommandDirectory $commandName
 Copy-Item -LiteralPath $env:ComSpec -Destination $firstCommand
 Copy-Item -LiteralPath $env:ComSpec -Destination (Join-Path $secondCommandDirectory $commandName)
 $commandEnvironment=Get-CiEnvironment $dir
 $commandEnvironment['PATH']=$firstCommandDirectory+';'+$secondCommandDirectory
 $commandScript=Join-Path $dir 'command-resolution.ps1';$commandJson=Join-Path $dir 'command-resolution.json'
 $commandPrefix=@'
param([string]$Out)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$candidates=@(Get-Command msbuild.exe -CommandType Application -All -ErrorAction Stop)
'@
 $commandSuffix=@'
@{count=$candidates.Count;selected=$selected;selectedType=$selected.GetType().FullName}|ConvertTo-Json|Set-Content -LiteralPath $Out
& $selected /d /c 'exit 7'
exit $LASTEXITCODE
'@
 # Evaluate the production assignment itself, so removing its scalar selection
 # causes this test to fail instead of leaving a separate test implementation.
 $commandSource=$commandPrefix+[Environment]::NewLine+'$selected='+$msbuildAssignments[0].Right.Extent.Text+[Environment]::NewLine+$commandSuffix
 [IO.File]::WriteAllText($commandScript,$commandSource)
 $job=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-File',$commandScript,$commandJson),$dir,$commandEnvironment,(Join-Path $dir 'command-resolution.log'));$jobs.Add($job);Wait-JobExit $job
 Require ($job.ExitCode -eq 7) 'CI_COMMAND_RESOLUTION_EXECUTION_FAILED'
 $commandObserved=Read-CiJson $commandJson
 Require ($commandObserved.count -eq 2 -and $commandObserved.selectedType -eq 'System.String' -and $commandObserved.selected -eq $firstCommand) 'CI_COMMAND_RESOLUTION_PRECEDENCE_FAILED';$count++
 # Verify that a real stage failure keeps its original safe identifier instead
 # of replacing it with a generic wrapper error. This creates no product build.
 $stageWork=Join-Path $dir 'stage-failure';[IO.Directory]::CreateDirectory((Join-Path $stageWork 'Railway'))|Out-Null
 $stageEnvironment=Get-CiEnvironment $stageWork;$stageEnvironment['BDS']=''
 $stageLog=Join-Path $dir 'stage-failure.log'
 $job=[GameCi.WindowsJob]::Start($exe,@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Windows-Stage.ps1'),'-Kind','build','-WorkRoot',$stageWork,'-Output',$stageWork),$dir,$stageEnvironment,$stageLog);$jobs.Add($job);Wait-JobExit $job
 Require ($job.ExitCode -eq 1) 'CI_SELFTEST_STAGE_FAILURE_EXIT'
 $detailLines=@(Get-Content -LiteralPath $stageLog|Where-Object{$_.StartsWith('CI_STAGE_DETAIL ')})
 Require ($detailLines.Count -eq 1) 'CI_SELFTEST_STAGE_DETAIL_MISSING'
 $stageDetail=$detailLines[0].Substring('CI_STAGE_DETAIL '.Length)|ConvertFrom-Json -AsHashtable
 Require ($stageDetail.stage -eq 'build' -and $stageDetail.error -eq 'CI_BDS_INVALID') 'CI_SELFTEST_STAGE_DETAIL_INVALID';$count++
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
} catch {
 $cause=$_.Exception;$failure='CI_RUNNER_SELFTEST_FAILED';$nativeCode=$null;$exceptionType=$cause.GetType().FullName
 for($depth=0;$null -ne $cause -and $depth -lt 8;$depth++){
  $exceptionType=$cause.GetType().FullName
  if($cause.Message -match '^CI_[A-Z0-9_]+$'){$failure=$cause.Message}
  if($cause -is [ComponentModel.Win32Exception]){$nativeCode=$cause.NativeErrorCode}
  $cause=$cause.InnerException
 }
 Write-Output ('CI_SELFTEST_DETAIL '+(@{error=$failure;exceptionType=$exceptionType;nativeErrorCode=$nativeCode}|ConvertTo-Json -Compress))
 exit 1
}finally{$cleanupError=$false;foreach($job in $jobs){try{$job.Dispose()}catch{$cleanupError=$true}};if($cleanupError){throw 'CI_SELFTEST_CLEANUP_FAILED'}}
