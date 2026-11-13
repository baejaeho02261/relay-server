param([Parameter(Mandatory)][string]$WorkRoot,[Parameter(Mandatory)][string]$Output,[Parameter(Mandatory)][string]$PrivateRoot,[Parameter(Mandatory)][string]$Version,[ValidateSet('','observe','prohibit')][string]$MitigationMode='',[string]$FixtureProfileKey='',[switch]$RevokeOverlay)
. (Join-Path $PSScriptRoot 'WindowsCommon.ps1')
$server=$null;$apps=$null;$bProcess=$null;$oProcess=$null;$success=$false;$result=@{version=1;outcome='FAIL';ready=$false;licenseConsumed=$false;overlayFirstFrame=$false;parentTransferred=$false;parentExited=$false;parentFilesDeleted=$false;overlayClosed=$false;serverSessionClosed=$false;fixtureEnrollmentApprovalUsed=$false;fixtureClaimObservationBarrierUsed=$false}
if($RevokeOverlay){$result.adminRevocation=@{cohortRevoked=$false;terminalDenialIssued=$false;overlayExited=$false;overlayFileDeleted=$false;noOwnedProcessesRemain=$false}}
function Test-FileNotFound([string]$File) {
 try { $null=[IO.File]::GetAttributes($File);return $false }
 catch {
  $cause=$_.Exception
  while($cause.InnerException){$cause=$cause.InnerException}
  if($cause -is [IO.FileNotFoundException]){return $true}
  throw
 }
}
function Save-FixtureFailure {
 # The private fixture directory is removed when the runner exits. Preserve
 # only its bounded error identifier in the public result, never input.json,
 # license material, server database contents or unfiltered exception text.
 $statusFile=Join-Path $run 'status.json'
 try {
  if(Test-Path -LiteralPath $statusFile){
   $failure=Read-TestJson $statusFile
   if($failure.ContainsKey('error') -and $failure.error -is [string] -and $failure.error -cmatch '^[A-Z][A-Z0-9_]{0,99}$'){$result.fixtureError=$failure.error}
  }
 } catch { }
}
function Assert-FixtureRunning {
 if($server.HasExited){Save-FixtureFailure;throw 'WINDOWS_TEST_FIXTURE_EXITED'}
}
try {
 Write-Output 'WINDOWS_TEST_INTEGRATION_BEGIN (real Release EXEs, local production TLS services)'
 if (-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { throw 'WINDOWS_TEST_INTERACTIVE_WINDOWS_SESSION_REQUIRED' }
 if($RevokeOverlay -and $MitigationMode){throw 'WINDOWS_TEST_INTEGRATION_MODE_INVALID'}
 $cohort=if($RevokeOverlay){'integration-revocation'}elseif($MitigationMode){'integration-profile-'+$MitigationMode}else{'integration'}
 $executionMode=if($RevokeOverlay){'revoke-overlay'}else{'interactive-close'}
 $run=Join-Path $PrivateRoot $cohort;New-TestPrivateDirectory $run
 $environment=Get-TestEnvironment $run;$node=(Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source;$web=Join-Path $WorkRoot 'Relay Server'
 if($MitigationMode){$null=Assert-TestOwnedPath $FixtureProfileKey $PrivateRoot}
 $server=[GameWindowsTests.WindowsJob]::Start($node,@((Join-Path $web 'tools\fixtures\peace.windows-fixture.js'),$run,$Output,$Version,$MitigationMode,$FixtureProfileKey,$executionMode),$web,$environment,(Join-Path $run 'server.log'))
 $clock=[Diagnostics.Stopwatch]::StartNew()
 do {
  Assert-FixtureRunning
  if(Test-Path -LiteralPath (Join-Path $run 'status.json')){
   $status=Read-TestJson (Join-Path $run 'status.json')
   if($status.ContainsKey('error')){Save-FixtureFailure;throw 'WINDOWS_TEST_FIXTURE_START_FAILED'}
   if($status.ready -and (Test-Path -LiteralPath (Join-Path $run 'input.json'))){break}
  }
  if($clock.Elapsed.TotalSeconds -gt 60){throw 'WINDOWS_TEST_FIXTURE_TIMEOUT'};Start-Sleep -Milliseconds 100
 } while($true)
 $input=Read-TestJson (Join-Path $run 'input.json');$launcher=Assert-TestOwnedPath $input.launcher (Join-Path $run 'execution');$result.ready=$true
 $apps=[GameWindowsTests.WindowsJob]::Start($launcher,@(),(Split-Path -Parent $launcher),$environment,(Join-Path $run 'application.log'))
 $bId=[uint32]0;$oId=[uint32]0;$bPath='';$oPath='';$sent=$false;$closed=$false;$frameAt=0.0;$revokeAt=0.0;$clock.Restart()
 do {
  Assert-FixtureRunning
  $status=Read-TestJson (Join-Path $run 'status.json')
  if($status.ContainsKey('fixtureEnrollmentApprovalUsed')){$result.fixtureEnrollmentApprovalUsed=$status.fixtureEnrollmentApprovalUsed -eq $true}
  if($status.ContainsKey('fixtureClaimObservationBarrierUsed')){$result.fixtureClaimObservationBarrierUsed=$status.fixtureClaimObservationBarrierUsed -eq $true}
  if($MitigationMode){if(-not $status.mitigationProfile.enabled -or $status.mitigationProfile.mode -ne $MitigationMode){throw 'WINDOWS_TEST_PROFILE_NOT_ACTIVE'};$result.mitigationMode=$MitigationMode;$result.profiledAuthorityStages=@($status.mitigationProfile.authorityStages)}
  if(-not $status.ready){Save-FixtureFailure;throw 'WINDOWS_TEST_FIXTURE_RUNTIME_FAILED'}
  $ids=@($apps.ProcessIds())
  if($bId -eq 0 -and $status.flowStatus -eq 'CLAIMED') {
   # NHW observer children use the owning EXE. Select only the direct A child
   # with a different image, then verify ownership on its retained handle.
   $children=@($apps.RootChildren()|Where-Object{
    $childImage=[GameWindowsTests.DesktopControl]::ImagePath([uint32]$_)
    $childImage -and -not [string]::Equals($childImage,$launcher,[StringComparison]::OrdinalIgnoreCase)
   })
   if($children.Count -eq 1){
    $bId=[uint32]$children[0];$bProcess=[Diagnostics.Process]::GetProcessById([int]$bId);$null=$bProcess.Handle
    if(-not $apps.OwnsProcess($bProcess.Handle)){throw 'WINDOWS_TEST_PROCESS_OWNERSHIP_LOST'}
    $bPath=Assert-TestOwnedPath ([GameWindowsTests.DesktopControl]::ImagePath($bId)) (Join-Path $run 'execution')
    $signalPath=Join-Path $run 'b-process-observed.signal';$signalTemporary=$signalPath+'.next'
    $signal=[IO.File]::Open($signalTemporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$bytes=[Text.Encoding]::ASCII.GetBytes("COZY_B_PROCESS_OBSERVED_V1`n");$signal.Write($bytes,0,$bytes.Length);$signal.Flush()}finally{$signal.Dispose()}
    [IO.File]::Move($signalTemporary,$signalPath)
   }
  }
  if($status.licenseUsed){$sent=$true;$input.licenseKey='';if(Test-Path -LiteralPath (Join-Path $run 'input.json')){Remove-Item -LiteralPath (Join-Path $run 'input.json') -Force}}
  if($bId -ne 0 -and -not $sent -and $input.licenseKey -and $ids -contains $bId){$sent=[GameWindowsTests.DesktopControl]::SubmitLicense($bId,[string]$input.licenseKey);if($sent){$input.licenseKey='';Remove-Item -LiteralPath (Join-Path $run 'input.json') -Force}}
  if($status.licenseUsed){$result.licenseConsumed=$true}
  if($status.overlayAuthorized -and $status.transferCommitted -and $oId -eq 0){
   # Only O owns a visible window after transfer. Its same-image observer
   # remains in the job and is still counted in the final empty-job check.
   $others=@($ids|Where-Object{$_ -ne $apps.RootId -and $_ -ne $bId -and [GameWindowsTests.DesktopControl]::Window([uint32]$_,$false)})
   if($others.Count -eq 1){$oId=[uint32]$others[0];$oProcess=[Diagnostics.Process]::GetProcessById([int]$oId);$null=$oProcess.Handle;if(-not $apps.OwnsProcess($oProcess.Handle)){throw 'WINDOWS_TEST_PROCESS_OWNERSHIP_LOST'};$oPath=Assert-TestOwnedPath ([GameWindowsTests.DesktopControl]::ImagePath($oId)) (Join-Path $run 'execution')}
  }
  if($oId -ne 0 -and [GameWindowsTests.DesktopControl]::Window($oId,$false)){$result.overlayFirstFrame=$true}
  if($status.transferCommitted -and $status.flowStatus -eq 'CLOSED' -and $status.retiredParent){$result.parentTransferred=$true}
  if($bId -ne 0 -and $ids -notcontains $bId -and $ids -notcontains $apps.RootId){if(-not $apps.HasExited -or $apps.ExitCode -ne 0 -or -not $bProcess.HasExited -or $bProcess.ExitCode -ne 0){throw 'WINDOWS_TEST_PARENT_EXIT_CODE'};$result.parentExited=$true}
  if($result.parentExited -and $bPath){
   if($RevokeOverlay){$result.parentFilesDeleted=(Test-FileNotFound $launcher) -and (Test-FileNotFound $bPath)}
   elseif(-not(Test-Path -LiteralPath $launcher) -and -not(Test-Path -LiteralPath $bPath)){$result.parentFilesDeleted=$true}
  }
  if($result.overlayFirstFrame -and $result.parentTransferred -and $result.parentFilesDeleted -and -not $closed -and $revokeAt -eq 0){
   if($frameAt -eq 0){$frameAt=$clock.Elapsed.TotalSeconds}
   # Observe the surviving overlay after B cleanup, not just a transient READY.
   if($clock.Elapsed.TotalSeconds-$frameAt -ge 2){
    if($RevokeOverlay){
     if($oProcess.HasExited -or $ids -notcontains $oId -or -not [GameWindowsTests.DesktopControl]::Window($oId,$false) -or (Test-FileNotFound $oPath)){throw 'WINDOWS_TEST_REVOCATION_OVERLAY_NOT_LIVE'}
     $request=Join-Path $run 'admin-revoke.request';$temporary=$request+'.next'
     $marker=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
     try{$bytes=[Text.Encoding]::ASCII.GetBytes('COZY_ADMIN_REVOKE_OVERLAY_V1');$marker.Write($bytes,0,$bytes.Length)}finally{$marker.Dispose()}
     $revokeAt=$clock.Elapsed.TotalSeconds
     [IO.File]::Move($temporary,$request)
    }else{$closed=[GameWindowsTests.DesktopControl]::Window($oId,$true)}
   }
  }
  if($RevokeOverlay){
   if($revokeAt -eq 0 -and $oId -ne 0 -and $oProcess.HasExited){throw 'WINDOWS_TEST_REVOCATION_OVERLAY_EARLY_EXIT'}
   if($revokeAt -gt 0){
    if($clock.Elapsed.TotalSeconds-$revokeAt -ge 15){throw 'WINDOWS_TEST_REVOCATION_OBSERVATION_TIMEOUT'}
    $result.adminRevocation.cohortRevoked=$status.adminRevocation.cohortRevoked -eq $true
    $result.adminRevocation.terminalDenialIssued=$status.adminRevocation.terminalDenialIssued -eq $true
    if($oProcess.HasExited){
     if($oProcess.ExitCode -ne 1){throw 'WINDOWS_TEST_REVOCATION_OVERLAY_EXIT_CODE'}
     $result.adminRevocation.overlayExited=$true
     $result.adminRevocation.overlayFileDeleted=Test-FileNotFound $oPath
     $result.adminRevocation.noOwnedProcessesRemain=$ids.Count -eq 0
    }
   }
   $terminal=$result.adminRevocation.Values -notcontains $false
  }else{
   if($closed -and $ids -notcontains $oId){if(-not $oProcess.HasExited -or $oProcess.ExitCode -ne 0){throw 'WINDOWS_TEST_OVERLAY_EXIT_CODE'};$result.overlayClosed=$true}
   if($status.overlayStatus -eq 'CLOSED' -and $status.retiredOverlay){$result.serverSessionClosed=$true}
   $terminal=$result.overlayClosed -and $result.serverSessionClosed
  }
  if($result.licenseConsumed -and $result.overlayFirstFrame -and $result.parentTransferred -and $result.parentExited -and $result.parentFilesDeleted -and $terminal -and $result.fixtureClaimObservationBarrierUsed){if($MitigationMode -and (@($result.profiledAuthorityStages).Count -ne 3 -or @('A','B','O').Where({$result.profiledAuthorityStages -notcontains $_}).Count -ne 0)){throw 'WINDOWS_TEST_PROFILE_AUTHORITY_OBSERVATION_MISSING'};$success=$true;break}
  if($clock.Elapsed.TotalSeconds -gt 180){throw 'WINDOWS_TEST_NATIVE_INTEGRATION_TIMEOUT'}
  if($ids.Count -eq 0 -and -not $closed -and $revokeAt -eq 0){throw 'WINDOWS_TEST_NATIVE_EARLY_EXIT'}
  Start-Sleep -Milliseconds 100
 } while($true)
 [IO.File]::WriteAllText((Join-Path $run 'stop.request'),'stop');$wait=[Diagnostics.Stopwatch]::StartNew()
 while(-not $server.HasExited -and $wait.Elapsed.TotalSeconds -lt 5){Start-Sleep -Milliseconds 100}
 if(-not $server.HasExited -or $server.ExitCode -ne 0){$success=$false;throw 'WINDOWS_TEST_SERVER_SHUTDOWN_FAILED'}
 $result.outcome='PASS';Write-Output 'WINDOWS_TEST_INTEGRATION_PASS'
} catch {
 $success=$false;$result.outcome='FAIL';$result.error='WINDOWS_TEST_INTEGRATION_EXCEPTION';$result.nativeErrorCode=$null
 $cause=$_.Exception
 for($depth=0;$null -ne $cause -and $depth -lt 8;$depth++){
  $result.exceptionType=$cause.GetType().FullName
  if($cause.Message -match '^WINDOWS_TEST_[A-Z0-9_]+$'){$result.error=$cause.Message}
  if($cause -is [ComponentModel.Win32Exception]){$result.nativeErrorCode=[int]$cause.NativeErrorCode}
  $cause=$cause.InnerException
 }
 $detail=@{error=$result.error;exceptionType=$result.exceptionType;nativeErrorCode=$result.nativeErrorCode}
 if($result.ContainsKey('fixtureError')){$detail.fixtureError=$result.fixtureError}
 Write-Output ('WINDOWS_TEST_INTEGRATION_DETAIL '+($detail|ConvertTo-Json -Compress))
 Write-Output $result.error
} finally {
 foreach($job in @($apps,$server)){if($job){try{$job.Dispose()}catch{$success=$false;$result.outcome='FAIL';$result.error='WINDOWS_TEST_JOB_CLEANUP_FAILED'}}};foreach($process in @($bProcess,$oProcess)){if($process){try{$process.Dispose()}catch{$success=$false;$result.outcome='FAIL';$result.error='WINDOWS_TEST_HANDLE_CLEANUP_FAILED'}}}
 $resultName=if($RevokeOverlay){'integration-revocation-result.json'}elseif($MitigationMode){'integration-profile-'+$MitigationMode+'-result.json'}else{'integration-result.json'}
 Write-TestJson (Join-Path $Output $resultName) $result
}
if($success){exit 0}else{exit 1}
