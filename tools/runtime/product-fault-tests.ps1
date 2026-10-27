param([string]$InputFile='',[string]$ResultFile='',[string]$GeneratedInputRoot='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$private=$null;$run=$null;$report=$null;$plan=$null;$node=$null;$cleanupTool=$null;$failureCode=$null;$exitCode=1
function Run-Tool([string]$Exe,[string[]]$Arguments,[string]$Directory,[string]$Log,[int]$Timeout=120){
 $job=$null
 try{$job=[GameWindowsTests.WindowsJob]::Start($Exe,$Arguments,$Directory,(Get-TestEnvironment $Directory),$Log);$clock=[Diagnostics.Stopwatch]::StartNew();while(-not $job.HasExited){if($clock.Elapsed.TotalSeconds -gt $Timeout){throw 'PRODUCT_FAULT_TOOL_TIMEOUT'};Start-Sleep -Milliseconds 100};if($job.ExitCode -ne 0){throw 'PRODUCT_FAULT_TOOL_FAILED'};if(@($job.ProcessIds()).Count -ne 0){throw 'PRODUCT_FAULT_TOOL_CHILD_LEAK'}}finally{if($job){$job.Dispose()}}
}
function Run-Case($Case,[string]$CaseRoot,[string]$Node,[string]$WorkRoot,[string]$RunId,[string]$Version){
 $server=$null;$apps=$null;$processes=@{};$verified=@{};$observedFiles=@{};$input=$null;$status=$null;$reused=$false;$sent=$false;$closed=$false;$nativeEvents=@();$licenseKey='';$eventDeadline=0.0;$leaseObserver=$null;$fileObserver=$null;$fileObserved=$false;$lateRelease=$false
 $result=@{scenario=$Case.id;runId=$RunId;nativeExecuted=$false;ownedProcessesVerified=$true;noOwnedProcessesRemain=$false;serverStopped=$false;privateFilesRemoved=$false;overlayObserved=$false;ownedChildTerminated=$false;parentExitObserved=$false;verifiedPids=@();nativeEvents=@()}
 try{
  # Compile the observer before the product reaches its bounded cleanup pause.
  if($Case.id -in @('lifecycle-cleanup-refused','lifecycle-cleanup-scheduled') -and -not ('GameWindowsTests.LifecycleFileObserver' -as [type])){Add-Type -Path (Join-Path $WorkRoot 'Relay Server\tools\fixtures\LifecycleFileObserver.cs')}
  New-TestPrivateDirectory $CaseRoot
  [IO.File]::WriteAllText((Join-Path $CaseRoot 'product-fault-marker'),'GAME_PRODUCT_FAULT_V1')
  Write-TestJson (Join-Path $CaseRoot 'product-fault-control.json') @{version=1;runId=$RunId;scenario=$Case.id}
  $environment=Get-TestEnvironment $CaseRoot
  if($Case.testBuild){$environment['GAME_PRODUCT_FAULT_ROOT']=$CaseRoot}
  $server=[GameWindowsTests.WindowsJob]::Start($Node,@((Join-Path $WorkRoot 'Relay Server\tools\fixtures\peace.product-fault-fixture.js'),$CaseRoot,$Case.artifacts,$Version,$Case.id,$RunId),(Join-Path $WorkRoot 'Relay Server'),$environment,(Join-Path $CaseRoot 'server.log'))
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while($true){
   if($server.HasExited){throw 'PRODUCT_FAULT_SERVER_EARLY_EXIT'}
   if(Test-Path -LiteralPath (Join-Path $CaseRoot 'status.json')){$status=Read-TestJson (Join-Path $CaseRoot 'status.json');if($status.ContainsKey('error')){throw ([string]$status.error)};if($status.ready -and (Test-Path -LiteralPath (Join-Path $CaseRoot 'input.json'))){break}}
   if($clock.Elapsed.TotalSeconds -gt 60){throw 'PRODUCT_FAULT_START_TIMEOUT'};Start-Sleep -Milliseconds 100
  }
  $input=Read-TestJson (Join-Path $CaseRoot 'input.json');$launcher=Assert-TestOwnedPath $input.launcher (Join-Path $CaseRoot 'execution');$licenseKey=[string]$input.licenseKey
  $result.expectedBHash=[string]$input.bSha512;if($result.expectedBHash -cnotmatch '^[a-f0-9]{128}$'){throw 'LIFECYCLE_EXPECTED_IMAGE_HASH_INVALID'}
  $apps=[GameWindowsTests.WindowsJob]::Start($launcher,@(),(Split-Path -Parent $launcher),$environment,(Join-Path $CaseRoot 'application.log'));$result.nativeExecuted=$true
  $clock.Restart();$bId=[uint32]0;$oId=[uint32]0
  do{
   if($server.HasExited){throw 'PRODUCT_FAULT_SERVER_EARLY_EXIT'}
   $status=Read-TestJson (Join-Path $CaseRoot 'status.json');if($status.ContainsKey('error')){throw ([string]$status.error)}
   $ids=@($apps.ProcessIds())
   foreach($id in $ids){
    if(-not $verified.ContainsKey([string]$id)){
     try{$process=[Diagnostics.Process]::GetProcessById([int]$id);$null=$process.Handle}catch{continue}
     if(-not $apps.OwnsProcess($process.Handle)){$process.Dispose();throw 'PRODUCT_FAULT_PROCESS_NOT_OWNED'}
     $image=[GameWindowsTests.DesktopControl]::ImagePath([uint32]$id);$null=Assert-TestOwnedPath $image (Join-Path $CaseRoot 'execution')
     $verified[[string]$id]=$image;$processes[[string]$id]=$process
    }
   }
   if($bId -eq 0 -and $status.flowStatus -eq 'CLAIMED'){$children=@($ids|Where-Object{$_ -ne $apps.RootId});if($children.Count -eq 1){$bId=[uint32]$children[0]}}
   if($status.licenseUsed){$sent=$true;$licenseKey='';$input.licenseKey='';if(Test-Path -LiteralPath (Join-Path $CaseRoot 'input.json')){Remove-Item -LiteralPath (Join-Path $CaseRoot 'input.json') -Force}}
   if($bId -ne 0 -and -not $sent -and $licenseKey -and $ids -contains $bId){$sent=[GameWindowsTests.DesktopControl]::SubmitLicense($bId,$licenseKey);if($sent){$licenseKey='';$input.licenseKey='';Remove-Item -LiteralPath (Join-Path $CaseRoot 'input.json') -Force}}
   if($oId -eq 0 -and $status.overlayAuthorized){$others=@($ids|Where-Object{$_ -ne $apps.RootId -and $_ -ne $bId});if($others.Count -eq 1){$oId=[uint32]$others[0]}}
   if($oId -ne 0){$result.overlayPid=[int]$oId}
   if($bId -ne 0){$result.parentPids=@{A=[int]$apps.RootId;B=[int]$bId}}
   if($Case.id -eq 'overlay-lease-expiry' -and $oId -ne 0 -and $null -eq $leaseObserver -and $processes.ContainsKey([string]$oId)){
    if(-not ('GameWindowsTests.OverlayLeaseObserver' -as [type])){Add-Type -Path (Join-Path $WorkRoot 'Relay Server\tools\fixtures\OverlayLeaseObserver.cs')}
    $leaseObserver=[GameWindowsTests.OverlayLeaseObserver]::new($oId,$processes[[string]$oId].Handle);$result.overlayPid=[int]$oId
   }
   if($oId -ne 0 -and [GameWindowsTests.DesktopControl]::Window($oId,$false)){$result.overlayObserved=$true}
   foreach($file in @(Get-ChildItem -LiteralPath $CaseRoot -Filter 'native-*.json' -File)){
    if($observedFiles.ContainsKey($file.Name)){continue}
    if($file.Length -gt 8192 -or $file.Name -cnotmatch '^native-([0-9]+)-([0-9]+)\.json$'){throw 'PRODUCT_FAULT_EVENT_INVALID'}
    try{$event=Read-TestJson $file.FullName}catch{continue}
    if($event.version -ne 1 -or $event.runId -ne $RunId -or $event.scenario -ne $Case.id -or -not $verified.ContainsKey([string]$event.pid)){throw 'PRODUCT_FAULT_EVENT_NOT_OWNED'}
    $observedFiles[$file.Name]=$true;$nativeEvents+=$event
    if($event.event -eq 'handoff-body-written' -and $Case.id -like 'handoff-child-exit-*'){
     $child=[string]$event.childPid
     $ownedNow=@($apps.ProcessIds())
     if($ownedNow -notcontains [uint32]$event.childPid){throw 'PRODUCT_FAULT_CHILD_NOT_OWNED'}
     if(-not $processes.ContainsKey($child)){
      $childProcess=[Diagnostics.Process]::GetProcessById([int]$event.childPid);$null=$childProcess.Handle
      if(-not $apps.OwnsProcess($childProcess.Handle)){$childProcess.Dispose();throw 'PRODUCT_FAULT_CHILD_NOT_OWNED'}
      $childImage=[GameWindowsTests.DesktopControl]::ImagePath([uint32]$event.childPid);$null=Assert-TestOwnedPath $childImage (Join-Path $CaseRoot 'execution')
      $processes[$child]=$childProcess;$verified[$child]=$childImage
     }
     if(-not $apps.OwnsProcess($processes[$child].Handle)){throw 'PRODUCT_FAULT_CHILD_NOT_OWNED'}
     # Terminate the held exact child handle. Never a name lookup or a foreign PID.
     $processes[$child].Kill();if(-not $processes[$child].WaitForExit(5000)){throw 'PRODUCT_FAULT_CHILD_EXIT_TIMEOUT'}
     $result.ownedChildTerminated=$true
     [IO.File]::WriteAllText((Join-Path $CaseRoot ('release-'+[string]$event.pid)),'continue')
    }
    if($event.event -eq 'lifecycle-cleanup-ready'){
     if($Case.id -notin @('lifecycle-cleanup-refused','lifecycle-cleanup-scheduled') -or $event.stage -ne 'lifecycle-parent-cleanup' -or $event.pid -ne $oId -or $event.childPid -ne $bId -or $null -ne $fileObserver -or -not $processes.ContainsKey([string]$bId) -or -not $processes[[string]$bId].HasExited){throw 'LIFECYCLE_PARENT_PAUSE_BINDING_INVALID'}
     if(-not ('GameWindowsTests.LifecycleFileObserver' -as [type])){Add-Type -Path (Join-Path $WorkRoot 'Relay Server\tools\fixtures\LifecycleFileObserver.cs')}
     $mode=if($Case.id -eq 'lifecycle-cleanup-refused'){'REFUSED'}else{'SCHEDULED'}
     $fileObserver=[GameWindowsTests.LifecycleFileObserver]::new([string]$verified[[string]$bId],[string]$result.expectedBHash,$mode,(Join-Path $CaseRoot 'execution'))
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
   if($bId -ne 0){
    $result.processObservations=@{}
    foreach($entry in @(@{role='A';pid=$apps.RootId},@{role='B';pid=$bId})){
     if($processes.ContainsKey([string]$entry.pid)){$held=$processes[[string]$entry.pid];$ended=$held.HasExited;$result.processObservations[$entry.role]=@{pid=[int]$entry.pid;exited=$ended;exitCode=if($ended){[int]$held.ExitCode}else{$null}}}
    }
   }
   # The native product reports through its real signed lifecycle endpoint.
   # Hold the exact B handle until the server has persisted that observation.
   if($null -ne $fileObserver -and -not $fileObserved -and $status.ContainsKey('lifecycle') -and $null -ne $status.lifecycle.flow){
    $expected=if($Case.id -eq 'lifecycle-cleanup-refused'){'FAILED'}else{'SCHEDULED'}
    $bReport=@($status.lifecycle.flow.events|Where-Object{$_.source -eq 'CLIENT_REPORTED' -and $_.role -eq 'B' -and $_.ContainsKey('reporterRole') -and $_.reporterRole -eq 'O' -and $_.event -eq 'FILE_CLEANUP' -and $_.status -eq $expected})
    if($bReport.Count -gt 0){
     $held=$fileObserver.Status();$result.lifecycleFile=@{mode=$expected;identity=$held.Identity;sha512=$held.Sha512;hashMatched=$held.HashMatched;heldSameIdentity=$held.HeldSameIdentity;initialPathMatched=$held.InitialPathMatched;heldPathMatches=$held.HeldPathMatches;heldPathError=$held.HeldPathError;handleError=$held.HandleError;deletePending=$held.DeletePending;pathAbsent=$held.PathAbsent;pathIdentityMatched=$held.PathIdentityMatched;pathError=$held.PathError;disposed=$held.Disposed;filePresentBefore=$held.FilePresentBefore}
     $fileObserver.Dispose();$waitRelease=[Diagnostics.Stopwatch]::StartNew()
     do{$released=$fileObserver.Status();if($released.AbsentAfterRelease -or $expected -eq 'FAILED'){break};Start-Sleep -Milliseconds 20}while($waitRelease.ElapsedMilliseconds -lt 2000)
     $result.lifecycleFile.afterReleaseDisposed=$released.Disposed;$result.lifecycleFile.absentAfterRelease=$released.AbsentAfterRelease;$fileObserved=$true
    }
   }
   if($Case.id -eq 'overlay-lease-expiry' -and -not $lateRelease -and $status.ContainsKey('lease') -and $status.lease.serverExpired -and @($nativeEvents|Where-Object{$_.event -eq 'lifecycle-late-report-ready' -and $_.pid -eq $oId}).Count -eq 1){
    [IO.File]::WriteAllText((Join-Path $CaseRoot ('release-late-'+[string]$oId)),'continue');$lateRelease=$true
   }
   if($Case.id -in @('lifecycle-cleanup-success','lifecycle-cleanup-scheduled') -and $result.overlayObserved -and $status.transferCommitted -and $result.ContainsKey('parentCleanupObserved') -and $result.parentCleanupObserved -and $status.ContainsKey('lifecycle') -and $null -ne $status.lifecycle.flow -and -not $closed){
    $bState=$status.lifecycle.flow.roles.B.fileCleanup
    if(($Case.id -eq 'lifecycle-cleanup-success' -and $bState -eq 'REMOVED') -or ($Case.id -eq 'lifecycle-cleanup-scheduled' -and $bState -eq 'SCHEDULED' -and $fileObserved)){$closed=[GameWindowsTests.DesktopControl]::Window($oId,$true)}
   }
   # Wait until the exact A and B are gone before arming: the transfer response
   # must already have reached B, so a pending B response cannot be mistaken
   # for corruption on the surviving O session.
   if($Case.id -eq 'tls-session-record-authentication-failure' -and $result.overlayObserved -and $status.transferCommitted -and $result.ContainsKey('parentCleanupObserved') -and $ids.Count -eq 1 -and $ids -contains $oId -and -not $result.ContainsKey('tlsArmRequestedAfterParentExit')){
    [IO.File]::WriteAllText((Join-Path $CaseRoot 'tls-arm.request'),'arm');$result.tlsArmRequestedAfterParentExit=$true
   }
   # Successful response-loss flows must leave a real visible O before closure.
   if($Case.id -like 'response-loss-*' -and $result.overlayObserved -and $status.transferCommitted -and $result.ContainsKey('parentCleanupObserved') -and $status.proof.retryObserved -and -not $closed){$closed=[GameWindowsTests.DesktopControl]::Window($oId,$true)}
   # GPU cases signal from the actual renderer HRESULT path. Close only our own
   # surviving O window after observation; failures before window creation exit.
   if($Case.id -like 'gpu-*' -and $eventDeadline -gt 0 -and $clock.Elapsed.TotalSeconds-$eventDeadline -gt 1 -and $oId -ne 0 -and -not $closed){$closed=[GameWindowsTests.DesktopControl]::Window($oId,$true)}
   if($Case.id -eq 'overlay-lease-expiry' -and $oId -ne 0 -and $processes.ContainsKey([string]$oId) -and $processes[[string]$oId].HasExited -and -not $result.ContainsKey('overlayExitTick')){
    # This path never posts WM_CLOSE and never kills O. The unchanged renderer
    # and shutdown guard respond to the real monotonic grant deadline.
    $result.overlayExitTick=[GameWindowsTests.OverlayLeaseObserver]::CurrentTick;$result.overlayExitCode=[int]$processes[[string]$oId].ExitCode
    $result.automaticExitObservedBeforeCleanup=($ids.Count -eq 0)
   }
   # Prove denial while the exact owned O is still alive, BEFORE releasing the
   # dedicated local-stop hold. Never change server time, tokens or lease rows.
   if($Case.id -eq 'authority-local-stop-held' -and $status.allAuthorityTerminal -and $status.ContainsKey('lease') -and $status.lease.serverExpired -and $oId -ne 0 -and $processes.ContainsKey([string]$oId) -and -not $processes[[string]$oId].HasExited){
    $result.overlayPid=[int]$oId
    if(-not $reused){[IO.File]::WriteAllText((Join-Path $CaseRoot 'reuse.request'),'check');$reused=$true}
    if($status.proof.reuseChecks -gt 0 -and $status.lease.oldAuthorityRejected){
     $result.serverDeniedWhileClientAlive=$true;$result.denialObservedAt=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
     $release=Join-Path $CaseRoot ('release-authority-'+[string]$oId)
     if(-not(Test-Path -LiteralPath $release)){[IO.File]::WriteAllText($release,'continue')}
    }
   }
   if($Case.id -like 'authority-*' -and $oId -ne 0){$result.overlayPid=[int]$oId}
   if($ids.Count -eq 0 -and $status.allAuthorityTerminal -and -not $reused){[IO.File]::WriteAllText((Join-Path $CaseRoot 'reuse.request'),'check');$reused=$true}
   if($reused -and $status.proof.reuseChecks -gt 0 -and ($Case.id -ne 'authority-local-stop-held' -or $ids.Count -eq 0)){$result.fixture=$status;break}
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
  if($fileObserver){try{$fileObserver.Dispose()}catch{$result.error='LIFECYCLE_OBSERVER_CLEANUP_FAILED'}}
  $jobsCleaned=$true;foreach($job in @($apps,$server)){if($job){try{$job.Dispose()}catch{$jobsCleaned=$false;$result.error='PRODUCT_FAULT_JOB_CLEANUP_FAILED'}}}
  $alive=$false;foreach($process in $processes.Values){try{if(-not $process.HasExited){$alive=$true}}catch{$alive=$true}finally{$process.Dispose()}}
  $result.noOwnedProcessesRemain=(-not $alive -and $jobsCleaned)
  $result.productFilesRemainingBeforeCleanup=@(Get-ChildItem -LiteralPath (Join-Path $CaseRoot 'execution') -Filter '*.exe' -File -ErrorAction SilentlyContinue).Count
  if(Test-Path -LiteralPath (Join-Path $CaseRoot 'product-fault-marker')){try{& $Node (Join-Path $WorkRoot 'Relay Server\tools\runtime\peace.test-evidence-cleanup.js') cleanup $CaseRoot;if($LASTEXITCODE -ne 0){throw 'PRODUCT_FAULT_PRIVATE_CLEANUP_FAILED'};$result.privateFilesRemoved=-not(Test-Path -LiteralPath $CaseRoot)}catch{$result.error='PRODUCT_FAULT_PRIVATE_CLEANUP_FAILED'}}
 }
 return $result
}
try{
 if(-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7){throw 'PRODUCT_FAULT_WINDOWS_POWERSHELL7_X64_REQUIRED'}
 if(-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'PRODUCT_FAULT_INTERACTIVE_DESKTOP_REQUIRED'}
 . (Join-Path $PSScriptRoot '..\..\tools\windows\WindowsCommon.ps1')
 $node=[string](Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
 $cleanupTool=Join-Path $PSScriptRoot 'peace.test-evidence-cleanup.js'
 if(-not $InputFile){$InputFile=(Read-Host 'Absolute product fault inputs JSON path').Trim().Trim('"')}
 $InputFile=[IO.Path]::GetFullPath($InputFile)
 $id='product-fault-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
 $run=Join-Path ([IO.Path]::GetTempPath()) ('GameProductFaultResults-'+[Guid]::NewGuid().ToString('N'));$private=Join-Path ([IO.Path]::GetTempPath()) ('GameProductFault-'+[Guid]::NewGuid().ToString('N'));$report=if($ResultFile){[IO.Path]::GetFullPath($ResultFile)}else{Join-Path $PSScriptRoot ($id+'-results.json')}
 if(Test-Path -LiteralPath $report){throw 'PRODUCT_FAULT_RESULT_MUST_BE_NEW'}
 New-TestPrivateDirectory $run;New-TestPrivateDirectory $private
 if(-not ('GameWindowsTests.LifecycleFileObserver' -as [type])){Add-Type -Path (Join-Path $root 'Relay Server\tools\fixtures\LifecycleFileObserver.cs')}
 # TEMP may contain ADMINI~1. Canonicalize validated directories before the
 # server and exact process-image comparisons see them, without relaxing pins.
 $run=[GameWindowsTests.LifecycleFileObserver]::CanonicalDirectory($run)
 $private=[GameWindowsTests.LifecycleFileObserver]::CanonicalDirectory($private)
 Write-Host 'Execution only. Final release and dedicated fault test builds have separate scopes. No build evidence is created.'
 Run-Tool $node @((Join-Path $PSScriptRoot 'peace.product-fault-tests.js'),'prepare',$InputFile,$run,$private) $private (Join-Path $run 'prepare.log')
 if($GeneratedInputRoot){
  $null=Assert-TestOwnedPath $InputFile $GeneratedInputRoot
  & $node $cleanupTool cleanup $GeneratedInputRoot
  if($LASTEXITCODE -ne 0){throw 'PRODUCT_FAULT_SELECTED_INPUT_CLEANUP_FAILED'}
 }
 $plan=Read-TestJson (Join-Path $run 'plan.json');$execution=@{version=1;scenarios=@();environment=@{platform='win32';architecture='x64';os=[Environment]::OSVersion.VersionString;powerShell=$PSVersionTable.PSVersion.ToString();interactive=[Environment]::UserInteractive}}
 foreach($case in $plan.scenarios){
  if($case.ContainsKey('skip')){Write-Host ($case.id+' NOT_RUN: '+$case.skip);continue}
  Write-Host ('RUN '+$case.id)
  $result=Run-Case $case (Join-Path $private $case.id) $node $root $plan.runId $plan.releaseVersion
  $execution.scenarios+=$result;Write-TestJson (Join-Path $run 'execution.json') $execution
 }
 if($plan.ContainsKey('nativeReceiveProbe')){
  $tlsResult=Join-Path $run 'native-receive.json'
  try{Run-Tool $node @((Join-Path $PSScriptRoot '..\integrity\peace.native-receive-fault-tests.js'),'--probe',$plan.nativeReceiveProbe,'--output',$tlsResult) $private (Join-Path $run 'native-receive.log') 180;$execution.nativeReceive=Read-TestJson $tlsResult}catch{if(Test-Path -LiteralPath $tlsResult){$execution.nativeReceive=Read-TestJson $tlsResult}else{$execution.nativeReceive=@{outcome='FAIL';reason='PRODUCT_FAULT_NATIVE_RECEIVE_FAILED'}}}
 }
 Write-TestJson (Join-Path $run 'execution.json') $execution
 $pending=Join-Path $run ([IO.Path]::GetFileName($report))
 try{Run-Tool $node @((Join-Path $PSScriptRoot 'peace.product-fault-tests.js'),'finalize',$run,$pending,$report) $private (Join-Path $run 'finalize.log')}catch{if(-not(Test-Path -LiteralPath $pending)){throw}}
 # Public files are created only after all private copies/logs are removed.
 # The helper retains exact bytes: companion evidence hashes cannot go stale.
 & $node $cleanupTool publish $run $private $pending $report
 if($LASTEXITCODE -ne 0){throw 'PRODUCT_FAULT_PRIVATE_CLEANUP_OR_PUBLICATION_FAILED'}
 $value=Read-TestJson $report;Write-Host ('Result: '+$value.outcome+' / '+$report);$exitCode=if($value.outcome -eq 'PASS'){0}elseif($value.outcome -eq 'INCOMPLETE'){2}else{1}
}catch{
 $code=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]+$'){$_.Exception.Message}else{'PRODUCT_FAULT_RUNNER_FAILED'};Write-Host ('ERROR: '+$code)
 $failureCode=$code
}finally{
 foreach($scratch in @($private,$run)){
  if($scratch -and $node -and $cleanupTool -and (Test-Path -LiteralPath $scratch)){
   & $node $cleanupTool cleanup $scratch
   if($LASTEXITCODE -ne 0){$exitCode=1;$failureCode='PRODUCT_FAULT_PRIVATE_CLEANUP_FAILED';Write-Host ('ERROR: '+$failureCode)}
  }
 }
}
if($failureCode -and $report -and $node -and $cleanupTool -and -not(Test-Path -LiteralPath $report)){& $node $cleanupTool failure $report PRODUCT_FAULT_EXECUTION $failureCode}
exit $exitCode
