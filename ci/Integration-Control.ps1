param([Parameter(Mandatory)][string]$WorkRoot,[Parameter(Mandatory)][string]$Output,[Parameter(Mandatory)][string]$PrivateRoot,[Parameter(Mandatory)][string]$Version)
. (Join-Path $PSScriptRoot 'CiCommon.ps1')
$server=$null;$apps=$null;$bProcess=$null;$oProcess=$null;$success=$false;$result=@{version=1;outcome='FAIL';ready=$false;licenseConsumed=$false;overlayFirstFrame=$false;parentTransferred=$false;parentExited=$false;parentFilesDeleted=$false;overlayClosed=$false;serverSessionClosed=$false}
try {
 Write-Output 'CI_INTEGRATION_BEGIN (real Release EXEs, local production TLS services)'
 if (-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'CI_INTERACTIVE_WINDOWS_SESSION_REQUIRED' }
 $run=Join-Path $PrivateRoot 'integration';New-CiPrivateDirectory $run
 $environment=Get-CiEnvironment $run;$node=(Get-Command node.exe).Source;$web=Join-Path $WorkRoot 'GameWeb'
 $server=[GameCi.WindowsJob]::Start($node,@((Join-Path $web 'ci\windows-fixture.js'),$run,$Output,$Version),$web,$environment,(Join-Path $run 'server.log'))
 $clock=[Diagnostics.Stopwatch]::StartNew()
 do {
  if($server.HasExited){throw 'CI_FIXTURE_EXITED'}
  if((Test-Path -LiteralPath (Join-Path $run 'input.json')) -and (Test-Path -LiteralPath (Join-Path $run 'status.json'))){$status=Read-CiJson (Join-Path $run 'status.json');if($status.ready){break};if($status.ContainsKey('error')){throw $status.error}}
  if($clock.Elapsed.TotalSeconds -gt 60){throw 'CI_FIXTURE_TIMEOUT'};Start-Sleep -Milliseconds 100
 } while($true)
 $input=Read-CiJson (Join-Path $run 'input.json');$launcher=Assert-CiOwnedPath $input.launcher (Join-Path $run 'execution');$result.ready=$true
 $apps=[GameCi.WindowsJob]::Start($launcher,@(),(Split-Path -Parent $launcher),$environment,(Join-Path $run 'application.log'))
 $bId=[uint32]0;$oId=[uint32]0;$bPath='';$sent=$false;$closed=$false;$frameAt=0.0;$clock.Restart()
 do {
  if($server.HasExited){throw 'CI_FIXTURE_EXITED'}
  $status=Read-CiJson (Join-Path $run 'status.json')
  if(-not $status.ready){throw 'CI_FIXTURE_RUNTIME_FAILED'}
  $ids=@($apps.ProcessIds())
  if($bId -eq 0 -and $status.flowStatus -eq 'CLAIMED') {
   $children=@($ids|Where-Object{$_ -ne $apps.RootId})
   if($children.Count -eq 1){$bId=[uint32]$children[0];$bProcess=[Diagnostics.Process]::GetProcessById([int]$bId);$null=$bProcess.Handle;if(-not $apps.OwnsProcess($bProcess.Handle)){throw 'CI_PROCESS_OWNERSHIP_LOST'};$bPath=Assert-CiOwnedPath ([GameCi.DesktopControl]::ImagePath($bId)) (Join-Path $run 'execution')}
  }
  if($bId -ne 0 -and -not $sent -and $ids -contains $bId){$sent=[GameCi.DesktopControl]::SubmitLicense($bId,[string]$input.licenseKey);if($sent){$input.licenseKey='';Remove-Item -LiteralPath (Join-Path $run 'input.json') -Force}}
  if($status.licenseUsed){$result.licenseConsumed=$true}
  if($status.overlayAuthorized -and $status.transferCommitted -and $oId -eq 0){
   $others=@($ids|Where-Object{$_ -ne $apps.RootId -and $_ -ne $bId})
   if($others.Count -eq 1){$oId=[uint32]$others[0];$oProcess=[Diagnostics.Process]::GetProcessById([int]$oId);$null=$oProcess.Handle;if(-not $apps.OwnsProcess($oProcess.Handle)){throw 'CI_PROCESS_OWNERSHIP_LOST'};$null=Assert-CiOwnedPath ([GameCi.DesktopControl]::ImagePath($oId)) (Join-Path $run 'execution')}
  }
  if($oId -ne 0 -and [GameCi.DesktopControl]::Window($oId,$false)){$result.overlayFirstFrame=$true}
  if($status.transferCommitted -and $status.flowStatus -eq 'CLOSED' -and $status.retiredParent){$result.parentTransferred=$true}
  if($bId -ne 0 -and $ids -notcontains $bId -and $ids -notcontains $apps.RootId){if(-not $apps.HasExited -or $apps.ExitCode -ne 0 -or -not $bProcess.HasExited -or $bProcess.ExitCode -ne 0){throw 'CI_PARENT_EXIT_CODE'};$result.parentExited=$true}
  if($result.parentExited -and -not(Test-Path -LiteralPath $launcher) -and $bPath -and -not(Test-Path -LiteralPath $bPath)){$result.parentFilesDeleted=$true}
  if($result.overlayFirstFrame -and $result.parentTransferred -and $result.parentFilesDeleted -and -not $closed){
   if($frameAt -eq 0){$frameAt=$clock.Elapsed.TotalSeconds}
   # Observe the surviving overlay after B cleanup, not just a transient READY.
   if($clock.Elapsed.TotalSeconds-$frameAt -ge 2){$closed=[GameCi.DesktopControl]::Window($oId,$true)}
  }
  if($closed -and $ids -notcontains $oId){if(-not $oProcess.HasExited -or $oProcess.ExitCode -ne 0){throw 'CI_OVERLAY_EXIT_CODE'};$result.overlayClosed=$true}
  if($status.overlayStatus -eq 'CLOSED' -and $status.retiredOverlay){$result.serverSessionClosed=$true}
  if($result.licenseConsumed -and $result.overlayFirstFrame -and $result.parentTransferred -and $result.parentExited -and $result.parentFilesDeleted -and $result.overlayClosed -and $result.serverSessionClosed){$success=$true;break}
  if($clock.Elapsed.TotalSeconds -gt 180){throw 'CI_NATIVE_INTEGRATION_TIMEOUT'}
  if($ids.Count -eq 0 -and -not $closed){throw 'CI_NATIVE_EARLY_EXIT'}
  Start-Sleep -Milliseconds 100
 } while($true)
 [IO.File]::WriteAllText((Join-Path $run 'stop.request'),'stop');$wait=[Diagnostics.Stopwatch]::StartNew()
 while(-not $server.HasExited -and $wait.Elapsed.TotalSeconds -lt 5){Start-Sleep -Milliseconds 100}
 if(-not $server.HasExited -or $server.ExitCode -ne 0){$success=$false;throw 'CI_SERVER_SHUTDOWN_FAILED'}
 $result.outcome='PASS';Write-Output 'CI_INTEGRATION_PASS'
} catch {
 $success=$false;$result.outcome='FAIL';$code=$_.Exception.Message
 $result.error=if($code -match '^CI_[A-Z0-9_]+$'){$code}else{'CI_INTEGRATION_EXCEPTION'}
 Write-Output $result.error
} finally {
 foreach($job in @($apps,$server)){if($job){try{$job.Dispose()}catch{$success=$false;$result.outcome='FAIL';$result.error='CI_JOB_CLEANUP_FAILED'}}};foreach($process in @($bProcess,$oProcess)){if($process){try{$process.Dispose()}catch{$success=$false;$result.outcome='FAIL';$result.error='CI_HANDLE_CLEANUP_FAILED'}}}
 Write-CiJson (Join-Path $Output 'integration-result.json') $result
}
if($success){exit 0}else{exit 1}
