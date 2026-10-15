param([string]$InputFile='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$run=$null;$private=$null;$report=$null;$execution=$null;$plan=$null;$node=$null
$resultCode=1
function Read-PathAnswer([string]$Prompt,[string]$Default='') {
 $value=(Read-Host $Prompt).Trim().Trim('"')
 if(-not $value){return $Default};return [IO.Path]::GetFullPath($value)
}
function Run-Owned([string]$Exe,[string[]]$Arguments,[string]$Log,[int]$Seconds) {
 $watch=[Diagnostics.Stopwatch]::StartNew();$job=$null
 $record=@{exitCode=$null;elapsedMs=0;outcome='FAIL'}
 try {
  $job=[GameCi.WindowsJob]::Start($Exe,$Arguments,$private,(Get-CiEnvironment $private),$Log)
  while(-not $job.HasExited){
   if($watch.Elapsed.TotalSeconds -gt $Seconds){throw 'MANUAL_PROCESS_TIMEOUT'}
   if((Get-Item -LiteralPath $Log).Length -gt 67108864){throw 'MANUAL_LOG_LIMIT'}
   Start-Sleep -Milliseconds 100
  }
  $record.exitCode=[int]$job.ExitCode
  $drain=[Diagnostics.Stopwatch]::StartNew()
  while(@($job.ProcessIds()).Count -gt 0 -and $drain.Elapsed.TotalSeconds -lt 3){Start-Sleep -Milliseconds 100}
  if(@($job.ProcessIds()).Count -gt 0){throw 'MANUAL_CHILD_PROCESS_LEAK'}
  $record.outcome=if($record.exitCode -eq 0){'EXECUTED'}else{'FAIL'}
 } catch {
  $record.error=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]+$'){$_.Exception.Message}else{'MANUAL_PROCESS_EXCEPTION'}
  $record.exceptionType=$_.Exception.GetType().FullName
 } finally {
  if($job){try{$job.Dispose()}catch{$record.outcome='FAIL';$record.error='MANUAL_PROCESS_CLEANUP_FAILED'}}
  $record.elapsedMs=[int64]$watch.Elapsed.TotalMilliseconds
 }
 return $record
}
try {
 if(-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7){throw 'MANUAL_WINDOWS_POWERSHELL7_X64_REQUIRED'}
 . (Join-Path $PSScriptRoot '..\ci\CiCommon.ps1')
 $node=[string](Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 $pwsh=[string](Get-Process -Id $PID).Path
 $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
 $id='manual-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
 $run=Join-Path $PSScriptRoot $id;$private=Join-Path ([IO.Path]::GetTempPath()) ('GameManual-'+[Guid]::NewGuid().ToString('N'))
 $report=Join-Path $PSScriptRoot ($id+'-results.json')
 New-CiPrivateDirectory $run;New-CiPrivateDirectory $private
 [IO.Directory]::CreateDirectory((Join-Path $run 'logs'))|Out-Null
 Write-Host 'Execution only: build the test projects in the RAD Studio IDE first.'
 Write-Host 'No command-line Delphi build, CI evidence, production key or production server is used.'
 Write-Host ('IDE group: '+(Join-Path $root 'GameConnect_Win64\tests\manual-ide\ManualNativeTests.groupproj'))
 if(-not $InputFile){
  $defaultBin=Join-Path $root 'GameConnect_Win64\tests\manual-ide\bin'
  $probeDirectory=Read-PathAnswer "Prebuilt probe folder [Enter: $defaultBin]" $defaultBin
  $answer=(Read-Host 'Also execute final Release A/B/O against a NEW isolated localhost test server? YES / NO [NO]').Trim()
  $integration=$answer -ceq 'YES';$artifacts=@{};$releaseVersion='1.0.0'
  if($integration){
   Write-Host ('Final Release EXE folder: '+(Join-Path $root 'GameConnect_Win64\bin'))
   foreach($role in @('A','B','O')){$artifacts[$role]=Read-PathAnswer ($role+' final Release EXE full path')}
   $releaseVersion=(Read-Host 'Actual numeric A/B/O version [Enter: 1.0.0]').Trim();if(-not $releaseVersion){$releaseVersion='1.0.0'}
  }
  $leaseAnswer=(Read-Host 'Also run the real 120-second O lease expiry using dedicated ProductFaults A/B/O builds? YES / NO [NO]').Trim()
  $faultArtifacts=@{}
  if($leaseAnswer -ceq 'YES'){
   Write-Host 'Use tests\product-faults\bin test builds. They are never publishable final EXEs. The runner waits for a genuine lease; no clock is changed.'
   foreach($role in @('A','B','O')){$faultArtifacts[$role]=Read-PathAnswer ($role+' dedicated fault-test EXE full path')}
   if(-not $integration){$releaseVersion=(Read-Host 'Actual numeric fault-test A/B/O version [Enter: 1.0.0]').Trim();if(-not $releaseVersion){$releaseVersion='1.0.0'}}
  }
  $verificationContext=''
  if($integration -and $faultArtifacts.Count -eq 3){$verificationContext=Read-PathAnswer 'Optional admin-exported verification-context JSON for build-linked expiry report [Enter: local result only]'}
  $hardwareAnswer=(Read-Host 'Also query this PC storage/NIC signals for a one-run hashed diagnostic? YES / NO [NO]').Trim()
  $collectHardwareSignals=$hardwareAnswer -ceq 'YES'
  $InputFile=Join-Path $PSScriptRoot ($id+'-inputs.json')
  $configuration=@{version=1;probeDirectory=$probeDirectory;probes=@{};artifacts=$artifacts;releaseVersion=$releaseVersion;runIntegration=$integration;collectHardwareSignals=$collectHardwareSignals}
  if($faultArtifacts.Count -eq 3){$configuration.faultArtifacts=$faultArtifacts};if($verificationContext){$configuration.verificationContext=$verificationContext}
  Write-CiJson $InputFile $configuration
 } else {$InputFile=[IO.Path]::GetFullPath($InputFile)}
 $execution=@{version=1;startedAt=[DateTime]::UtcNow.ToString('o');environment=@{os=[Environment]::OSVersion.VersionString;powerShell=$PSVersionTable.PSVersion.ToString();processBits=64;interactive=[Environment]::UserInteractive;sessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;nodePath=$node};stages=@()}
 $openssl=if(Get-Command openssl.exe -CommandType Application -ErrorAction SilentlyContinue){'true'}else{'false'}
 $prepare=Run-Owned $node @((Join-Path $PSScriptRoot 'manual-windows-tests.js'),'prepare',$InputFile,$run,$private,$node,$pwsh,$openssl) (Join-Path $run 'prepare.log') 90
 if($prepare.exitCode -ne 0 -or $prepare.ContainsKey('error')){throw 'MANUAL_PREPARATION_FAILED_SEE_PREPARE_LOG'}
 $plan=Read-CiJson (Join-Path $run 'plan.json')
 foreach($stage in $plan.stages){
  if($stage.id -in @('deterministic-state','independent-pe','independent-crc') -and -not $stage.ContainsKey('skip')){
   $pythonAvailable=$false
   foreach($candidate in @($env:PYTHON,'python3.exe','python.exe')){if($candidate -and (Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue)){$pythonAvailable=$true;break}}
   if(-not $pythonAvailable){$stage.skip='PYTHON_REQUIRED_FOR_INDEPENDENT_REFERENCE_ONLY'}
  }
  if($stage.ContainsKey('skip')){$skipStatus=if($stage.ContainsKey('preparationError')){'FAIL'}else{'NOT_RUN'};Write-Host ($stage.id+' '+$skipStatus+': '+$stage.skip);$execution.stages+=@{id=$stage.id;outcome=$skipStatus;reason=$stage.skip};continue}
  Write-Host ('RUN '+$stage.id)
  $record=Run-Owned ([string]$stage.exe) ([string[]]$stage.args) (Join-Path $run ('logs\'+$stage.id+'.log')) ([int]$stage.timeoutSeconds)
  $record.id=$stage.id;$execution.stages+=$record
  Write-CiJson (Join-Path $run 'execution.json') $execution
 }
 if($plan.ContainsKey('overlayLeaseExpiry')){
  $leaseStage=$plan.overlayLeaseExpiry
  if($leaseStage.ContainsKey('skip')){$execution.overlayLeaseExpiry=@{outcome='NOT_RUN';reason=$leaseStage.skip};Write-Host ('overlay-lease-expiry NOT_RUN: '+$leaseStage.skip)}
  else{Write-Host 'RUN overlay-lease-expiry (real 120-second grant; dedicated test builds)';$execution.overlayLeaseExpiry=Run-Owned ([string]$leaseStage.exe) ([string[]]$leaseStage.args) (Join-Path $run 'logs\overlay-lease-expiry.log') ([int]$leaseStage.timeoutSeconds)}
 }
 Write-CiJson (Join-Path $run 'execution.json') $execution
 Write-CiJson (Join-Path $run 'plan.json') $plan
 # Final hash/result validation runs before private fixture copies are removed.
 $finish=Run-Owned $node @((Join-Path $PSScriptRoot 'manual-windows-tests.js'),'finalize',$run,$report) (Join-Path $run 'finalize.log') 90
 if($finish.ContainsKey('error') -or -not(Test-Path -LiteralPath $report)){throw 'MANUAL_RESULT_FINALIZATION_FAILED'}
 $value=Read-CiJson $report;Write-Host ('Result: '+$value.outcome+' / '+$report)
 if($value.ContainsKey('publicVerificationFile')){Write-Host ('Admin manual execution record: '+$value.publicVerificationFile)}
 if($value.ContainsKey('leaseVerificationFile')){Write-Host ('Admin build-linked expiry observation (dedicated test builds): '+$value.leaseVerificationFile)}
 Write-Host 'MANUAL_EXECUTION only. Physical DPI, GPU/driver loss and RDP checks remain separately recorded.'
 $resultCode=if($value.outcome -eq 'PASS'){0}elseif($value.outcome -eq 'INCOMPLETE'){2}else{1}
} catch {
 $code=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]+$'){$_.Exception.Message}else{'MANUAL_RUNNER_FAILED'}
 Write-Host ('ERROR: '+$code)
 if($report -and -not(Test-Path -LiteralPath $report)){
  $failure=@{version=1;kind='MANUAL_EXECUTION';outcome='FAIL';error=$code;nativeBuild='NOT_RUN';ciEvidenceCreated=$false;hardwareAttested=$false;publicationApproval=$false;stages=if($execution){$execution.stages}else{@()};finishedAt=[DateTime]::UtcNow.ToString('o')}
  [IO.File]::WriteAllText($report,($failure|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false));Write-Host ('Result: '+$report)
 }
} finally {
 if($private -and (Test-Path -LiteralPath (Join-Path $private 'ci-owned-marker'))){
  try{Remove-Item -LiteralPath $private -Recurse -Force}catch{
   Write-Host ('ERROR: MANUAL_PRIVATE_FIXTURE_CLEANUP_FAILED '+$private);$resultCode=1
   if($report -and (Test-Path -LiteralPath $report)){$value=Read-CiJson $report;$value.outcome='FAIL';$value.cleanup='MANUAL_PRIVATE_FIXTURE_CLEANUP_FAILED';Write-CiJson $report $value}
  }
 }
}
exit $resultCode
