param([string]$InputFile='',[string]$ResultFile='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$private=$null;$run=$null;$report=$null;$plan=$null;$exitCode=1
function Run-Tool([string]$Exe,[string[]]$Arguments,[string]$Directory,[string]$Log,[int]$Timeout=120){
 $job=$null
 try{$job=[GameCi.WindowsJob]::Start($Exe,$Arguments,$Directory,(Get-CiEnvironment $Directory),$Log);$clock=[Diagnostics.Stopwatch]::StartNew();while(-not $job.HasExited){if($clock.Elapsed.TotalSeconds -gt $Timeout){throw 'PRODUCT_FAULT_TOOL_TIMEOUT'};Start-Sleep -Milliseconds 100};if($job.ExitCode -ne 0){throw 'PRODUCT_FAULT_TOOL_FAILED'};if(@($job.ProcessIds()).Count -ne 0){throw 'PRODUCT_FAULT_TOOL_CHILD_LEAK'}}finally{if($job){$job.Dispose()}}
}
function Run-Case($Case,[string]$CaseRoot,[string]$Node,[string]$WorkRoot,[string]$RunId,[string]$Version){
 $server=$null;$apps=$null;$processes=@{};$verified=@{};$observedFiles=@{};$input=$null;$status=$null;$reused=$false;$sent=$false;$closed=$false;$nativeEvents=@();$licenseKey='';$eventDeadline=0.0;$leaseObserver=$null
 $result=@{scenario=$Case.id;runId=$RunId;nativeExecuted=$false;ownedProcessesVerified=$true;noOwnedProcessesRemain=$false;serverStopped=$false;privateFilesRemoved=$false;overlayObserved=$false;ownedChildTerminated=$false;parentExitObserved=$false;verifiedPids=@();nativeEvents=@()}
 try{
  New-CiPrivateDirectory $CaseRoot
  [IO.File]::WriteAllText((Join-Path $CaseRoot 'product-fault-marker'),'GAME_PRODUCT_FAULT_V1')
  Write-CiJson (Join-Path $CaseRoot 'product-fault-control.json') @{version=1;runId=$RunId;scenario=$Case.id}
  $environment=Get-CiEnvironment $CaseRoot
  if($Case.testBuild){$environment['GAME_PRODUCT_FAULT_ROOT']=$CaseRoot}
  $server=[GameCi.WindowsJob]::Start($Node,@((Join-Path $WorkRoot 'GameWeb\ci\product-fault-fixture.js'),$CaseRoot,$Case.artifacts,$Version,$Case.id,$RunId),(Join-Path $WorkRoot 'GameWeb'),$environment,(Join-Path $CaseRoot 'server.log'))
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while($true){
   if($server.HasExited){throw 'PRODUCT_FAULT_SERVER_EARLY_EXIT'}
   if(Test-Path -LiteralPath (Join-Path $CaseRoot 'status.json')){$status=Read-CiJson (Join-Path $CaseRoot 'status.json');if($status.ContainsKey('error')){throw ([string]$status.error)};if($status.ready -and (Test-Path -LiteralPath (Join-Path $CaseRoot 'input.json'))){break}}
   if($clock.Elapsed.TotalSeconds -gt 60){throw 'PRODUCT_FAULT_START_TIMEOUT'};Start-Sleep -Milliseconds 100
  }
  $input=Read-CiJson (Join-Path $CaseRoot 'input.json');$launcher=Assert-CiOwnedPath $input.launcher (Join-Path $CaseRoot 'execution');$licenseKey=[string]$input.licenseKey
  $apps=[GameCi.WindowsJob]::Start($launcher,@(),(Split-Path -Parent $launcher),$environment,(Join-Path $CaseRoot 'application.log'));$result.nativeExecuted=$true
  $clock.Restart();$bId=[uint32]0;$oId=[uint32]0
  do{
   if($server.HasExited){throw 'PRODUCT_FAULT_SERVER_EARLY_EXIT'}
   $status=Read-CiJson (Join-Path $CaseRoot 'status.json');if($status.ContainsKey('error')){throw ([string]$status.error)}
   $ids=@($apps.ProcessIds())
   foreach($id in $ids){
    if(-not $verified.ContainsKey([string]$id)){
     try{$process=[Diagnostics.Process]::GetProcessById([int]$id);$null=$process.Handle}catch{continue}
     if(-not $apps.OwnsProcess($process.Handle)){$process.Dispose();throw 'PRODUCT_FAULT_PROCESS_NOT_OWNED'}
     $image=[GameCi.DesktopControl]::ImagePath([uint32]$id);$null=Assert-CiOwnedPath $image (Join-Path $CaseRoot 'execution')
     $verified[[string]$id]=$image;$processes[[string]$id]=$process
    }
   }
   if($bId -eq 0 -and $status.flowStatus -eq 'CLAIMED'){$children=@($ids|Where-Object{$_ -ne $apps.RootId});if($children.Count -eq 1){$bId=[uint32]$children[0]}}
   if($bId -ne 0 -and -not $sent -and $ids -contains $bId){$sent=[GameCi.DesktopControl]::SubmitLicense($bId,$licenseKey);if($sent){$licenseKey='';$input.licenseKey='';Remove-Item -LiteralPath (Join-Path $CaseRoot 'input.json') -Force}}
   if($oId -eq 0 -and $status.overlayAuthorized){$others=@($ids|Where-Object{$_ -ne $apps.RootId -and $_ -ne $bId});if($others.Count -eq 1){$oId=[uint32]$others[0]}}
   if($Case.id -eq 'overlay-lease-expiry' -and $oId -ne 0 -and $null -eq $leaseObserver -and $processes.ContainsKey([string]$oId)){
    if(-not ('GameCi.OverlayLeaseObserver' -as [type])){Add-Type -Path (Join-Path $WorkRoot 'GameWeb\ci\OverlayLeaseObserver.cs')}
    $leaseObserver=[GameCi.OverlayLeaseObserver]::new($oId,$processes[[string]$oId].Handle);$result.overlayPid=[int]$oId
   }
   if($oId -ne 0 -and [GameCi.DesktopControl]::Window($oId,$false)){$result.overlayObserved=$true}
   foreach($file in @(Get-ChildItem -LiteralPath $CaseRoot -Filter 'native-*.json' -File)){
    if($observedFiles.ContainsKey($file.Name)){continue}
    if($file.Length -gt 8192 -or $file.Name -cnotmatch '^native-([0-9]+)-([0-9]+)\.json$'){throw 'PRODUCT_FAULT_EVENT_INVALID'}
    try{$event=Read-CiJson $file.FullName}catch{continue}
    if($event.version -ne 1 -or $event.runId -ne $RunId -or $event.scenario -ne $Case.id -or -not $verified.ContainsKey([string]$event.pid)){throw 'PRODUCT_FAULT_EVENT_NOT_OWNED'}
    $observedFiles[$file.Name]=$true;$nativeEvents+=$event
    if($event.event -eq 'handoff-body-written' -and $Case.id -like 'handoff-child-exit-*'){
     $child=[string]$event.childPid
     $ownedNow=@($apps.ProcessIds())
     if($ownedNow -notcontains [uint32]$event.childPid){throw 'PRODUCT_FAULT_CHILD_NOT_OWNED'}
     if(-not $processes.ContainsKey($child)){
      $childProcess=[Diagnostics.Process]::GetProcessById([int]$event.childPid);$null=$childProcess.Handle
      if(-not $apps.OwnsProcess($childProcess.Handle)){$childProcess.Dispose();throw 'PRODUCT_FAULT_CHILD_NOT_OWNED'}
      $childImage=[GameCi.DesktopControl]::ImagePath([uint32]$event.childPid);$null=Assert-CiOwnedPath $childImage (Join-Path $CaseRoot 'execution')
      $processes[$child]=$childProcess;$verified[$child]=$childImage
     }
     if(-not $apps.OwnsProcess($processes[$child].Handle)){throw 'PRODUCT_FAULT_CHILD_NOT_OWNED'}
     # Terminate the held exact child handle. Never a name lookup or a foreign PID.
     $processes[$child].Kill();if(-not $processes[$child].WaitForExit(5000)){throw 'PRODUCT_FAULT_CHILD_EXIT_TIMEOUT'}
     $result.ownedChildTerminated=$true
     [IO.File]::WriteAllText((Join-Path $CaseRoot ('release-'+[string]$event.pid)),'continue')
    }
    if($event.event -eq 'fault-observed' -and $eventDeadline -eq 0){$eventDeadline=$clock.Elapsed.TotalSeconds}
   }
   if($Case.id -like 'handoff-parent-exit-*'){
    foreach($event in $nativeEvents){if($event.event -eq 'fault-observed' -and $processes.ContainsKey([string]$event.pid) -and $processes[[string]$event.pid].HasExited){$result.parentExitObserved=$true;$result.parentExitCode=[int]$processes[[string]$event.pid].ExitCode}}
   }
   if($bId -ne 0 -and $processes.ContainsKey([string]$apps.RootId) -and $processes.ContainsKey([string]$bId) -and $ids -notcontains $apps.RootId -and $ids -notcontains $bId){
    $aProcess=$processes[[string]$apps.RootId];$bProcess=$processes[[string]$bId]
    if($aProcess.HasExited -and $bProcess.HasExited -and $aProcess.ExitCode -eq 0 -and $bProcess.ExitCode -eq 0 -and -not(Test-Path -LiteralPath $launcher) -and -not(Test-Path -LiteralPath $verified[[string]$bId])){$result.parentCleanupObserved=$true}
   }
   # Wait until the exact A and B are gone before arming: the transfer response
   # must already have reached B, so a pending B response cannot be mistaken
   # for corruption on the surviving O session.
   if($Case.id -eq 'tls-session-record-authentication-failure' -and $result.overlayObserved -and $status.transferCommitted -and $result.ContainsKey('parentCleanupObserved') -and $ids.Count -eq 1 -and $ids -contains $oId -and -not $result.ContainsKey('tlsArmRequestedAfterParentExit')){
    [IO.File]::WriteAllText((Join-Path $CaseRoot 'tls-arm.request'),'arm');$result.tlsArmRequestedAfterParentExit=$true
   }
   # Successful response-loss flows must leave a real visible O before closure.
   if($Case.id -like 'response-loss-*' -and $result.overlayObserved -and $status.transferCommitted -and $result.ContainsKey('parentCleanupObserved') -and $status.proof.retryObserved -and -not $closed){$closed=[GameCi.DesktopControl]::Window($oId,$true)}
   # GPU cases signal from the actual renderer HRESULT path. Close only our own
   # surviving O window after observation; failures before window creation exit.
   if($Case.id -like 'gpu-*' -and $eventDeadline -gt 0 -and $clock.Elapsed.TotalSeconds-$eventDeadline -gt 1 -and $oId -ne 0 -and -not $closed){$closed=[GameCi.DesktopControl]::Window($oId,$true)}
   if($Case.id -eq 'overlay-lease-expiry' -and $oId -ne 0 -and $processes.ContainsKey([string]$oId) -and $processes[[string]$oId].HasExited -and -not $result.ContainsKey('overlayExitTick')){
    # This path never posts WM_CLOSE and never kills O. The unchanged renderer
    # and shutdown guard respond to the real monotonic grant deadline.
    $result.overlayExitTick=[GameCi.OverlayLeaseObserver]::CurrentTick;$result.overlayExitCode=[int]$processes[[string]$oId].ExitCode
    $result.automaticExitObservedBeforeCleanup=($ids.Count -eq 0)
   }
   if($ids.Count -eq 0 -and $status.allAuthorityTerminal -and -not $reused){[IO.File]::WriteAllText((Join-Path $CaseRoot 'reuse.request'),'check');$reused=$true}
   if($reused -and $status.proof.reuseChecks -gt 0){$result.fixture=$status;break}
   if($clock.Elapsed.TotalSeconds -gt 450){throw 'PRODUCT_FAULT_CASE_TIMEOUT'}
   Start-Sleep -Milliseconds 50
  }while($true)
  [IO.File]::WriteAllText((Join-Path $CaseRoot 'stop.request'),'stop');$stop=[Diagnostics.Stopwatch]::StartNew()
  while(-not $server.HasExited -and $stop.Elapsed.TotalSeconds -lt 8){Start-Sleep -Milliseconds 100}
  if(-not $server.HasExited -or $server.ExitCode -ne 0){throw 'PRODUCT_FAULT_SERVER_SHUTDOWN_FAILED'};$result.serverStopped=$true
 }catch{
  $result.error=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]+$'){$_.Exception.Message}else{'PRODUCT_FAULT_EXECUTION_EXCEPTION'}
  if($status){$result.fixture=$status}
 }finally{
  $licenseKey='';if($input){$input.licenseKey=''}
  $result.verifiedPids=@($verified.Keys|ForEach-Object{[int]$_});$result.nativeEvents=$nativeEvents
  if($leaseObserver){
   try{$leaseObserver.Dispose();if($leaseObserver.Failed){$result.error='LEASE_OBSERVER_FAILED'}}catch{$result.error='LEASE_OBSERVER_CLEANUP_FAILED'}
   $result.leaseWindow=@{pid=[int]$oId;windowHandle=$leaseObserver.WindowHandle;visibleAt=$leaseObserver.VisibleAt;hiddenAt=$leaseObserver.HiddenAt;visibleTick=$leaseObserver.VisibleTick;hiddenTick=$leaseObserver.HiddenTick;hiddenWhileAlive=$leaseObserver.HiddenWhileAlive;reappeared=$leaseObserver.Reappeared;failed=$leaseObserver.Failed}
  }
  $jobsCleaned=$true;foreach($job in @($apps,$server)){if($job){try{$job.Dispose()}catch{$jobsCleaned=$false;$result.error='PRODUCT_FAULT_JOB_CLEANUP_FAILED'}}}
  $alive=$false;foreach($process in $processes.Values){try{if(-not $process.HasExited){$alive=$true}}catch{$alive=$true}finally{$process.Dispose()}}
  $result.noOwnedProcessesRemain=(-not $alive -and $jobsCleaned)
  $result.productFilesRemainingBeforeCleanup=@(Get-ChildItem -LiteralPath (Join-Path $CaseRoot 'execution') -Filter '*.exe' -File -ErrorAction SilentlyContinue).Count
  if(Test-Path -LiteralPath (Join-Path $CaseRoot 'product-fault-marker')){try{Remove-Item -LiteralPath $CaseRoot -Recurse -Force;$result.privateFilesRemoved=-not(Test-Path -LiteralPath $CaseRoot)}catch{$result.error='PRODUCT_FAULT_PRIVATE_CLEANUP_FAILED'}}
 }
 return $result
}
try{
 if(-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7){throw 'PRODUCT_FAULT_WINDOWS_POWERSHELL7_X64_REQUIRED'}
 if(-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'PRODUCT_FAULT_INTERACTIVE_DESKTOP_REQUIRED'}
 . (Join-Path $PSScriptRoot '..\ci\CiCommon.ps1')
 $node=[string](Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
 if(-not $InputFile){$InputFile=(Read-Host 'Absolute product fault inputs JSON path').Trim().Trim('"')}
 $InputFile=[IO.Path]::GetFullPath($InputFile)
 $id='product-fault-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
 $run=Join-Path $PSScriptRoot $id;$private=Join-Path ([IO.Path]::GetTempPath()) ('GameProductFault-'+[Guid]::NewGuid().ToString('N'));$report=if($ResultFile){[IO.Path]::GetFullPath($ResultFile)}else{Join-Path $PSScriptRoot ($id+'-results.json')}
 if(Test-Path -LiteralPath $report){throw 'PRODUCT_FAULT_RESULT_MUST_BE_NEW'}
 New-CiPrivateDirectory $run;New-CiPrivateDirectory $private
 Write-Host 'Execution only. Final release and dedicated fault test builds have separate scopes. No build or CI evidence is created.'
 Run-Tool $node @((Join-Path $PSScriptRoot 'product-fault-tests.js'),'prepare',$InputFile,$run,$private) $private (Join-Path $run 'prepare.log')
 $plan=Read-CiJson (Join-Path $run 'plan.json');$execution=@{version=1;scenarios=@();environment=@{platform='win32';architecture='x64';os=[Environment]::OSVersion.VersionString;powerShell=$PSVersionTable.PSVersion.ToString();interactive=[Environment]::UserInteractive}}
 foreach($case in $plan.scenarios){
  if($case.ContainsKey('skip')){Write-Host ($case.id+' NOT_RUN: '+$case.skip);continue}
  Write-Host ('RUN '+$case.id)
  $result=Run-Case $case (Join-Path $private $case.id) $node $root $plan.runId $plan.releaseVersion
  $execution.scenarios+=$result;Write-CiJson (Join-Path $run 'execution.json') $execution
 }
 if($plan.ContainsKey('nativeReceiveProbe')){
  $tlsResult=Join-Path $run 'native-receive.json'
  try{Run-Tool $node @((Join-Path $PSScriptRoot 'native-receive-fault-tests.js'),'--probe',$plan.nativeReceiveProbe,'--output',$tlsResult) $private (Join-Path $run 'native-receive.log') 180;$execution.nativeReceive=Read-CiJson $tlsResult}catch{if(Test-Path -LiteralPath $tlsResult){$execution.nativeReceive=Read-CiJson $tlsResult}else{$execution.nativeReceive=@{outcome='FAIL';reason='PRODUCT_FAULT_NATIVE_RECEIVE_FAILED'}}}
 }
 Write-CiJson (Join-Path $run 'execution.json') $execution
 try{Run-Tool $node @((Join-Path $PSScriptRoot 'product-fault-tests.js'),'finalize',$run,$report) $private (Join-Path $run 'finalize.log')}catch{if(-not(Test-Path -LiteralPath $report)){throw}}
 $value=Read-CiJson $report;Write-Host ('Result: '+$value.outcome+' / '+$report);$exitCode=if($value.outcome -eq 'PASS'){0}elseif($value.outcome -eq 'INCOMPLETE'){2}else{1}
}catch{
 $code=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]+$'){$_.Exception.Message}else{'PRODUCT_FAULT_RUNNER_FAILED'};Write-Host ('ERROR: '+$code)
 if($report -and -not(Test-Path -LiteralPath $report)){Write-CiJson $report @{version=1;kind='PRODUCT_FAULT_EXECUTION';outcome='FAIL';reason=$code;nativeBuild='NOT_RUN';ciEvidenceCreated=$false;hardwareAttested=$false;publicationApproval=$false}}
}finally{
 if($private -and (Test-Path -LiteralPath (Join-Path $private 'ci-owned-marker'))){try{Remove-Item -LiteralPath $private -Recurse -Force}catch{$exitCode=1;if($report -and (Test-Path -LiteralPath $report)){$value=Read-CiJson $report;$value.outcome='FAIL';$value.cleanup='PRODUCT_FAULT_PRIVATE_CLEANUP_FAILED';Write-CiJson $report $value}}}
}
exit $exitCode
