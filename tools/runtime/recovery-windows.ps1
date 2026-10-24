param([string]$InputFile='', [string]$ResultFile='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$private=$null;$server=$null;$apps=$null;$node=$null;$report=$null;$plan=$null;$status=$null;$processes=@{};$exitCode=1;$naturalAppsEmpty=$false
$input=$null;$stage=$null;$pending=$null;$cleanupTool=$null;$failureCode=$null;$failureIdentity=$null
$result=@{version=1;windowsExecuted=$false;platform='win32';architecture='x64';ownedProcessesVerified=$true;noOwnedProcessesRemain=$false;serverStopped=$false;licenseConsumed=$false;overlayFirstFrame=$false;parentTransferred=$false;parentExited=$false;parentFilesDeleted=$false;overlayClosed=$false;serverSessionClosed=$false}
function Tool([string[]]$Arguments,[string]$Log){
 $job=$null
 try{$directory=if($Arguments.Count -gt 1 -and $Arguments[1] -eq 'finalize'){$PSScriptRoot}else{$private};$job=[GameCi.WindowsJob]::Start($node,$Arguments,$directory,(Get-CiEnvironment $private),$Log);$watch=[Diagnostics.Stopwatch]::StartNew();while(-not $job.HasExited){if($watch.Elapsed.TotalSeconds -gt 240){throw 'RECOVERY_WINDOWS_TOOL_TIMEOUT'};Start-Sleep -Milliseconds 100};if($job.ExitCode -ne 0){$code='RECOVERY_WINDOWS_TOOL_FAILED';if((Test-Path -LiteralPath $Log) -and (Get-Item -LiteralPath $Log).Length -lt 1048576){foreach($line in @(Get-Content -LiteralPath $Log -Tail 20)){if($line -cmatch '^[A-Z][A-Z0-9_]{2,100}$'){$code=[string]$line}}};throw $code};if(@($job.ProcessIds()).Count -ne 0){throw 'RECOVERY_WINDOWS_TOOL_CHILD_LEAK'}}finally{if($job){$job.Dispose()}}
}
try{
 if(-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7){throw 'RECOVERY_WINDOWS_POWERSHELL7_X64_REQUIRED'}
 if(-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'RECOVERY_WINDOWS_INTERACTIVE_DESKTOP_REQUIRED'}
 . (Join-Path $PSScriptRoot '..\..\ci\pipeline\CiCommon.ps1')
 $cleanupTool=Join-Path $PSScriptRoot 'peace.test-evidence-cleanup.js'
 $node=[string](Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 if(-not $InputFile){$InputFile=(Read-Host 'Absolute recovery-windows input JSON path').Trim().Trim('"')}
 $InputFile=[IO.Path]::GetFullPath($InputFile)
 $name='recovery-windows-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
 $report=if($ResultFile){[IO.Path]::GetFullPath($ResultFile)}else{Join-Path $PSScriptRoot ($name+'-results.json')}
 if(-not ('GameCi.LifecycleFileObserver' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot '..\..\ci\fixtures\LifecycleFileObserver.cs')}
 $report=Join-Path ([GameCi.LifecycleFileObserver]::CanonicalDirectory([IO.Path]::GetDirectoryName($report))) ([IO.Path]::GetFileName($report))
 if(Test-Path -LiteralPath $report){throw 'RECOVERY_WINDOWS_RESULT_MUST_BE_NEW'}
 $private=Join-Path ([IO.Path]::GetTempPath()) ('game-recovery-drill-'+[Guid]::NewGuid().ToString('N'));New-CiPrivateDirectory $private
 Write-Host 'Isolated recovery of a read-only backup. Original device key is opened only; a new exclusive namespace is removed after the drill.'
 Write-Host 'The selected original Windows user/device, copied witness and already approved active A/B/O are required. No CI approval is created.'
 Tool @((Join-Path $PSScriptRoot '..\recovery\peace.recovery-windows.js'),'prepare',$InputFile,$private) (Join-Path $private 'prepare.log')
 $plan=Read-CiJson (Join-Path $private 'plan.json');$private=[IO.Path]::GetDirectoryName([string]$plan.data);$result.runId=[string]$plan.runId
 if(-not(Test-Path -LiteralPath (Join-Path $private 'ci-owned-marker'))){throw 'RECOVERY_WINDOWS_PRIVATE_ROOT_REQUIRED'}
 $environment=Get-CiEnvironment $private
 $server=[GameCi.WindowsJob]::Start($node,@((Join-Path $PSScriptRoot '..\recovery\peace.recovery-windows-fixture.js'),$private),([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))),$environment,(Join-Path $private 'server.log'))
 $watch=[Diagnostics.Stopwatch]::StartNew();$lastPhase=''
 do{
  if(Test-Path -LiteralPath (Join-Path $private 'status.json')){$status=Read-CiJson (Join-Path $private 'status.json');if($status.ContainsKey('error')){throw ([string]$status.error)};if($status.phase -ne $lastPhase){$lastPhase=[string]$status.phase;Write-Host ('Recovery phase: '+$lastPhase)};if($status.ready -and (Test-Path -LiteralPath (Join-Path $private 'input.json'))){break}}
  if($server.HasExited){throw 'RECOVERY_WINDOWS_SERVER_EARLY_EXIT'};if($watch.Elapsed.TotalSeconds -gt 420){throw 'RECOVERY_WINDOWS_PREPARATION_TIMEOUT'};Start-Sleep -Milliseconds 100
 }while($true)
 $input=Read-CiJson (Join-Path $private 'input.json');$launcher=Assert-CiOwnedPath $input.launcher (Join-Path $private 'execution')
 # The server-assigned path has no plaintext license to retain or submit.
 if($input.automaticLicense){Remove-Item -LiteralPath (Join-Path $private 'input.json') -Force}
 $apps=[GameCi.WindowsJob]::Start($launcher,@(),(Split-Path -Parent $launcher),$environment,(Join-Path $private 'application.log'));$result.windowsExecuted=$true
 $aProcess=[Diagnostics.Process]::GetProcessById([int]$apps.RootId);$null=$aProcess.Handle;if(-not $apps.OwnsProcess($aProcess.Handle)){$aProcess.Dispose();throw 'RECOVERY_WINDOWS_PROCESS_NOT_OWNED'};$processes[[string]$apps.RootId]=$aProcess
 $bId=[uint32]0;$oId=[uint32]0;$bPath='';$sent=$false;$closed=$false;$visibleAt=0.0;$watch.Restart()
 do{
  if($server.HasExited){throw 'RECOVERY_WINDOWS_SERVER_EARLY_EXIT'}
  $status=Read-CiJson (Join-Path $private 'status.json');if($status.ContainsKey('error')){throw ([string]$status.error)}
  if($status.runId -ne $plan.runId -or -not $status.ready){throw 'RECOVERY_WINDOWS_FIXTURE_BINDING_LOST'}
  $ids=@($apps.ProcessIds())
  foreach($childId in @($ids|Where-Object{$_ -ne $apps.RootId})){
   if($processes.ContainsKey([string]$childId)){continue}
   $p=[Diagnostics.Process]::GetProcessById([int]$childId);$null=$p.Handle
   if(-not $apps.OwnsProcess($p.Handle)){$p.Dispose();throw 'RECOVERY_WINDOWS_PROCESS_NOT_OWNED'}
   $image=Assert-CiOwnedPath ([GameCi.DesktopControl]::ImagePath([uint32]$childId)) (Join-Path $private 'execution')
   $hash=(Get-FileHash -LiteralPath $image -Algorithm SHA512).Hash.ToLowerInvariant()
   if($hash -ceq [string]$plan.files.B.sha512 -and $bId -eq 0){$bId=[uint32]$childId;$bPath=$image}
   elseif($hash -ceq [string]$plan.files.O.sha512 -and $oId -eq 0){$oId=[uint32]$childId}
   else{$p.Dispose();throw 'RECOVERY_WINDOWS_CHILD_ARTIFACT_MISMATCH'}
   $processes[[string]$childId]=$p
  }
  if(-not $input.automaticLicense -and $bId -ne 0 -and -not $sent -and $ids -contains $bId){$sent=[GameCi.DesktopControl]::SubmitLicense($bId,[string]$input.licenseKey);if($sent){$input.licenseKey='';Remove-Item -LiteralPath (Join-Path $private 'input.json') -Force}}
  if($status.licenseUsed){$result.licenseConsumed=$true;$sent=$true;if($input.ContainsKey('licenseKey')){$input.licenseKey='';$input.Remove('licenseKey')};if(Test-Path -LiteralPath (Join-Path $private 'input.json')){Remove-Item -LiteralPath (Join-Path $private 'input.json') -Force}}
  if($oId -ne 0 -and [GameCi.DesktopControl]::Window($oId,$false)){$result.overlayFirstFrame=$true}
  if($status.transferCommitted -and $status.retiredParent -and $status.flowStatus -eq 'CLOSED'){$result.parentTransferred=$true}
  if($bId -ne 0 -and $ids -notcontains $bId -and $ids -notcontains $apps.RootId){if(-not $aProcess.HasExited -or $aProcess.ExitCode -ne 0 -or -not $processes[[string]$bId].HasExited -or $processes[[string]$bId].ExitCode -ne 0){throw 'RECOVERY_WINDOWS_PARENT_EXIT_FAILED'};$result.parentExited=$true}
  if($result.parentExited -and -not(Test-Path -LiteralPath $launcher) -and $bPath -and -not(Test-Path -LiteralPath $bPath)){$result.parentFilesDeleted=$true}
  if($result.overlayFirstFrame -and $result.parentTransferred -and $result.parentFilesDeleted -and $status.product.allRolesProvedReplacement -and -not $closed){if($visibleAt -eq 0){$visibleAt=$watch.Elapsed.TotalSeconds};if($watch.Elapsed.TotalSeconds-$visibleAt -ge 2){$closed=[GameCi.DesktopControl]::Window($oId,$true)}}
  if($closed -and $ids -notcontains $oId){if(-not $processes[[string]$oId].HasExited -or $processes[[string]$oId].ExitCode -ne 0){throw 'RECOVERY_WINDOWS_OVERLAY_EXIT_FAILED'};$result.overlayClosed=$true}
  if($status.overlayStatus -eq 'CLOSED' -and $status.retiredOverlay -and $status.product.runtimeRetired){$result.serverSessionClosed=$true}
  if($result.licenseConsumed -and $result.overlayFirstFrame -and $result.parentTransferred -and $result.parentExited -and $result.parentFilesDeleted -and $result.overlayClosed -and $result.serverSessionClosed){if(@($apps.ProcessIds()).Count -ne 0){throw 'RECOVERY_WINDOWS_UNEXPECTED_PRODUCT_CHILD'};$naturalAppsEmpty=$true;$result.cleanupHadToTerminateOwnedProcess=$false;break}
  if($ids.Count -eq 0 -and -not $closed){throw 'RECOVERY_WINDOWS_PRODUCT_EARLY_EXIT'};if($watch.Elapsed.TotalSeconds -gt 300){throw 'RECOVERY_WINDOWS_PRODUCT_TIMEOUT'};Start-Sleep -Milliseconds 100
 }while($true)
 [IO.File]::WriteAllText((Join-Path $private 'stop.request'),'stop');$watch.Restart();while(-not $server.HasExited -and $watch.Elapsed.TotalSeconds -lt 100){Start-Sleep -Milliseconds 100}
 if(-not $server.HasExited -or $server.ExitCode -ne 0 -or @($server.ProcessIds()).Count -ne 0){throw 'RECOVERY_WINDOWS_SERVER_SHUTDOWN_FAILED'};$result.serverStopped=$true
}catch{
 $result.error=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]{2,100}$'){$_.Exception.Message}else{'RECOVERY_WINDOWS_RUNNER_FAILED'};Write-Host ('ERROR: '+$result.error)
}finally{
 if($input -and $input.ContainsKey('licenseKey')){$input.licenseKey='';$input.Remove('licenseKey')}
 if($private -and (Test-Path -LiteralPath (Join-Path $private 'input.json'))){try{Remove-Item -LiteralPath (Join-Path $private 'input.json') -Force}catch{}}
 if($server -and -not $server.HasExited -and $private){try{[IO.File]::WriteAllText((Join-Path $private 'stop.request'),'stop');$wait=[Diagnostics.Stopwatch]::StartNew();while(-not $server.HasExited -and $wait.Elapsed.TotalSeconds -lt 20){Start-Sleep -Milliseconds 100}}catch{}}
 foreach($job in @($apps,$server)){if($job){try{$job.Dispose()}catch{$result.error='RECOVERY_WINDOWS_JOB_CLEANUP_FAILED'}}}
 $alive=$false;foreach($p in $processes.Values){try{if(-not $p.HasExited){$alive=$true}}catch{$alive=$true}finally{$p.Dispose()}};$result.noOwnedProcessesRemain=($naturalAppsEmpty -and -not $alive)
 if($private -and $plan){
  try{
   Write-CiJson (Join-Path $private 'execution.json') $result
   if(-not(Test-Path -LiteralPath (Join-Path $private 'status.json'))){Write-CiJson (Join-Path $private 'status.json') @{version=1;runId=$plan.runId;error='RECOVERY_WINDOWS_STATUS_MISSING'}}
   $lastStatus=Read-CiJson (Join-Path $private 'status.json');if($lastStatus.ContainsKey('recovery') -and $lastStatus.recovery.ContainsKey('replacementCleanup')){$failureIdentity=$lastStatus.recovery.replacementCleanup}
   # Finalize removes the recovered server copy. Public report and companion
   # stay in a separate ACL-protected stage until its helper log is removed.
   $stage=Join-Path ([IO.Path]::GetTempPath()) ('game-recovery-report-'+[Guid]::NewGuid().ToString('N'));New-CiPrivateDirectory $stage
   $stage=[GameCi.LifecycleFileObserver]::CanonicalDirectory($stage)
   $pending=Join-Path $stage ([IO.Path]::GetFileName($report))
   try{Tool @((Join-Path $PSScriptRoot '..\recovery\peace.recovery-windows.js'),'finalize',$private,$pending,$report) (Join-Path $stage 'finalize.log')}catch{if(-not(Test-Path -LiteralPath $pending)){throw};$partial=Read-CiJson $pending;if($partial.outcome -ne 'FAIL'){throw}}
   $pendingResult=Read-CiJson $pending
   if($pendingResult.ContainsKey('checks') -and $pendingResult.checks.ContainsKey('replacementCleanup')){$failureIdentity=$pendingResult.checks.replacementCleanup}
   # Reads exact report/companion bytes, removes the stage and every helper log,
   # then publishes both; no PASS companion is exposed before scratch cleanup.
   & $node $cleanupTool publish-one $stage $pending $report
   if($LASTEXITCODE -ne 0){throw 'RECOVERY_WINDOWS_CLEANUP_OR_PUBLICATION_FAILED'}
  }catch{
   $failureCode=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]{2,100}$'){$_.Exception.Message}else{'RECOVERY_WINDOWS_FINALIZATION_FAILED'}
   Write-Host ('ERROR: '+$failureCode+'; no successful publication is claimed.')
  }
 }
 if($stage -and $node -and $cleanupTool -and (Test-Path -LiteralPath $stage)){
  & $node $cleanupTool cleanup $stage
  if($LASTEXITCODE -ne 0){$failureCode='RECOVERY_WINDOWS_REPORT_STAGE_CLEANUP_FAILED';Write-Host ('ERROR: '+$failureCode)}
 }
 if($failureCode -and $report -and -not(Test-Path -LiteralPath $report)){
  $failed=@{version=1;kind='RECOVERY_WINDOWS_PRODUCT_DRILL';outcome='FAIL';error=$failureCode;nativeBuild='NOT_RUN';ciEvidenceCreated=$false;hardwareAttested=$false;publicationApproval=$false}
  if($failureIdentity){$failed.checks=@{replacementCleanup=$failureIdentity}}
  try{Write-CiJson $report $failed}catch{Write-Host 'ERROR: Bounded recovery failure result could not be saved.'}
 }
 if($report -and (Test-Path -LiteralPath $report)){$final=Read-CiJson $report;$exitCode=if($final.outcome -eq 'PASS' -and -not $failureCode){0}else{1};Write-Host ('Result: '+$final.outcome+' / '+$report)}
 if($failureCode){$exitCode=1}
 if($private -and (Test-Path -LiteralPath (Join-Path $private 'ci-owned-marker'))){try{Remove-Item -LiteralPath $private -Recurse -Force}catch{$exitCode=1;Write-Host 'ERROR: Isolated recovery files could not be removed.'}}
}
exit $exitCode
