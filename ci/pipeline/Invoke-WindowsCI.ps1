param(
 [string]$SourceRoot=(Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),
 [Parameter(Mandatory)][string]$OutputDirectory,
 [Parameter(Mandatory)][ValidatePattern('^\d+(?:\.\d+){0,3}$')][string]$Version,
 [ValidateRange(1,2147483647)][int]$SecurityVersion=1,
 [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]{1,100}$')][string]$RunId,
 [Parameter(Mandatory)][string]$BuildInputLockFile,
 [string]$BdsRoot=$env:BDS,[string]$ReleaseKeyFile,[string]$CiKeyFile,[string]$PolicyFile
)
# All outputs are observations of actual subprocesses, never operator PASS input.
. (Join-Path $PSScriptRoot 'CiCommon.ps1')
$private=$null;$output=$null;$work=$null;$exit=1;$active=$null
$results=@{version=1;runId=$RunId;releaseVersion=$Version;securityVersion=$SecurityVersion;productionKeysPresent=$false;windowsExecuted=$true;stages=[ordered]@{};nativeBuild='NOT_RUN';apiProbe='NOT_RUN';integration='NOT_RUN';signed=$false}
foreach($name in @('build-inputs-before-dependencies','self-test','snapshot','dependencies','build-inputs','build','build-inputs-after','normalize','approve','native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare','integration','security-authority','profile-integration-observe','profile-integration-prohibit','report')){$results.stages[$name]=@{outcome='NOT_RUN';exitCode=$null;elapsedMs=0}}
function Save-Results {if($output){Write-CiJson (Join-Path $output 'runner-results.json') $results}}
function Invoke-CiCommand([string]$Name,[string]$Exe,[string[]]$Arguments,[string]$Directory,[int]$Seconds) {
 $watch=[Diagnostics.Stopwatch]::StartNew();$job=$null;$record=$results.stages[$Name]
 try {
  Write-Output "CI_RUNNING $Name"
  $job=[GameCi.WindowsJob]::Start($Exe,$Arguments,$Directory,(Get-CiEnvironment $private),(Join-Path $output ('logs\'+$Name+'.log')))
  while(-not $job.HasExited){
   if($watch.Elapsed.TotalSeconds -gt $Seconds){throw 'CI_STAGE_TIMEOUT'}
   if((Get-Item -LiteralPath (Join-Path $output ('logs\'+$Name+'.log'))).Length -gt 64MB){throw 'CI_LOG_LIMIT'}
   Start-Sleep -Milliseconds 100
  }
  $record.exitCode=[int64]$job.ExitCode
  if($record.exitCode -ne 0){throw 'CI_STAGE_NONZERO_EXIT'}
  $drain=[Diagnostics.Stopwatch]::StartNew()
  while(@($job.ProcessIds()).Count -ne 0 -and $drain.Elapsed.TotalSeconds -lt 2){Start-Sleep -Milliseconds 50}
  if(@($job.ProcessIds()).Count -ne 0){throw 'CI_STAGE_ORPHAN_PROCESS'}
  $record.outcome='PASS'
 } catch {
  $record.outcome='FAIL';if($null -eq $record.exitCode){$record.exitCode=-1}
  # Static error identifiers and numeric OS errors are safe to report. Never
  # print arbitrary exception messages, arguments, environment values or keys.
  $safeErrors=@('CI_STAGE_TIMEOUT','CI_LOG_LIMIT','CI_STAGE_NONZERO_EXIT','CI_STAGE_ORPHAN_PROCESS',
   'CI_X64_REQUIRED','CI_JOB_CREATE','CI_JOB_LIMIT','CI_LOG_CREATE','CI_INPUT_CREATE',
   'CI_HANDLE_LIST_SIZE','CI_HANDLE_LIST_INIT','CI_HANDLE_LIST_SET','CI_ENV_INVALID',
   'CI_PROCESS_CREATE','CI_JOB_ASSIGN','CI_PROCESS_RESUME','CI_PROCESS_STATUS',
   'CI_JOB_QUERY','CI_JOB_COUNT','CI_JOB_CLEANUP_TIMEOUT')
  $record.error='CI_STAGE_EXCEPTION';$record.nativeErrorCode=$null
  $exceptionCursor=$_.Exception
  for($depth=0;$null -ne $exceptionCursor -and $depth -lt 8;$depth++) {
   $record.exceptionType=$exceptionCursor.GetType().FullName
   if($safeErrors -ccontains $exceptionCursor.Message){$record.error=$exceptionCursor.Message}
   if($exceptionCursor -is [ComponentModel.Win32Exception]){$record.nativeErrorCode=[int]$exceptionCursor.NativeErrorCode}
   $exceptionCursor=$exceptionCursor.InnerException
  }
  Write-Output ('CI_STAGE_DETAIL '+(@{stage=$Name;error=$record.error;exceptionType=$record.exceptionType;nativeErrorCode=$record.nativeErrorCode}|ConvertTo-Json -Compress))
  throw "CI_STAGE_FAILED_$Name"
 } finally {$cleanupFailed=$false;if($job){try{$job.Dispose()}catch{$record.outcome='FAIL';$record.error='CI_JOB_CLEANUP_FAILED';$cleanupFailed=$true}};$record.elapsedMs=[int64]$watch.Elapsed.TotalMilliseconds;Save-Results;if($cleanupFailed){throw 'CI_JOB_CLEANUP_FAILED'}}
}
function Stage([string]$Kind,[int]$Seconds=600,[string]$Key='') {
 $stageArgs=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $work 'Relay Server\ci\pipeline\Windows-Stage.ps1'),'-Kind',$Kind,'-WorkRoot',$work,'-Output',$output,'-Version',$Version,'-SecurityVersion',[string]$SecurityVersion,'-RunId',$RunId)
 if($Key){throw 'CI_PRODUCTION_KEY_ARGUMENT_FORBIDDEN'}
 $stageArgs+=@('-BuildInputLockFile',(Join-Path $private 'reviewed-build-inputs.json'))
 if($Kind -eq 'approve'){$stageArgs+=@('-PrivateDirectory',$private);if($PolicyFile){$stageArgs+=@('-PolicyFile',(Join-Path $private 'reviewed-policy.json'))}}
 Invoke-CiCommand $Kind (Join-Path $PSHOME 'pwsh.exe') $stageArgs $work $Seconds
}

try {
 if($ReleaseKeyFile -or $CiKeyFile -or $env:GAME_RELEASE_APPROVAL_KEY_B64 -or $env:GAME_CI_ATTESTATION_KEY_B64){throw 'CI_PRODUCTION_KEYS_FORBIDDEN_ON_BUILDER'}
 if(-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'CI_INTERACTIVE_RUNNER_REQUIRED'}
 if(-not $BdsRoot -or -not(Test-Path -LiteralPath (Join-Path $BdsRoot 'bin\dcc64.exe'))){throw 'CI_RAD_STUDIO_REQUIRED'}
 $env:BDS=(Resolve-Path -LiteralPath $BdsRoot).ProviderPath
 $source=(Resolve-Path -LiteralPath $SourceRoot).ProviderPath
 $output=[IO.Path]::GetFullPath($OutputDirectory);New-CiPrivateDirectory $output
 [IO.Directory]::CreateDirectory((Join-Path $output 'logs'))|Out-Null
 $private=Join-Path ([IO.Path]::GetTempPath()) ('GameWindowsCI-'+[Guid]::NewGuid().ToString('N'));New-CiPrivateDirectory $private
 $work=Join-Path $private 'source'
 if(-not(Test-Path -LiteralPath $BuildInputLockFile -PathType Leaf)){throw 'CI_REVIEWED_BUILD_INPUT_LOCK_REQUIRED'}
 $lock=Get-Item -LiteralPath $BuildInputLockFile;if($lock.Length -gt 32MB -or ($lock.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CI_BUILD_INPUT_LOCK_INVALID'}
 [IO.File]::Copy($lock.FullName,(Join-Path $private 'reviewed-build-inputs.json'),$false)
 # The reviewed record is external input. Observation never approves it.
 $reviewedBootstrap=Read-CiJson (Join-Path $private 'reviewed-build-inputs.json')
 function Assert-BootstrapInput([string]$Key,[string]$File) {
  $expected=$reviewedBootstrap.files[$Key]
  if($expected -cnotmatch '^[a-f0-9]{128}$'){throw 'CI_BUILD_TOOL_LOCK_REQUIRED'}
  $item=Get-Item -LiteralPath $File -ErrorAction Stop
  if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA512).Hash.ToLowerInvariant() -cne $expected){throw 'CI_UNAPPROVED_BUILD_TOOL'}
 }
 Assert-BootstrapInput 'toolchain/pwsh/executable' (Join-Path $PSHOME 'pwsh.exe')
 Assert-BootstrapInput 'toolchain/cmd/executable' $env:ComSpec
 Assert-BootstrapInput 'bds/bin/rsvars.bat' (Join-Path $env:BDS 'bin\rsvars.bat')
 # Resolve the same RAD/Visual Studio PATH before collecting any executable.
 $radEnvironment=& $env:ComSpec /d /c ('call "'+(Join-Path $env:BDS 'bin\rsvars.bat')+'" >nul && set')
 if($LASTEXITCODE -ne 0){throw 'CI_RAD_ENV_FAILED'}
 foreach($line in $radEnvironment){$at=$line.IndexOf('=');if($at -gt 0){[Environment]::SetEnvironmentVariable($line.Substring(0,$at),$line.Substring($at+1))}}
 $env:PYTHONDONTWRITEBYTECODE='1'
 $env:NODE_GYP_FORCE_PYTHON=(Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
 $node=(Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
 Assert-BootstrapInput 'toolchain/node/executable' $node
 Invoke-CiCommand 'build-inputs-before-dependencies' $node @((Join-Path $source 'Relay Server\ci\toolchain\peace.build-input-lock.js'),'verify',(Join-Path $source 'Railway'),(Join-Path $source 'Relay Server'),$env:BDS,(Join-Path $private 'reviewed-build-inputs.json'),(Join-Path $output 'build-inputs-before-dependencies.json')) $source 600
 $null=Get-Command openssl.exe -CommandType Application -ErrorAction Stop
 $null=Get-Command cl.exe -CommandType Application -ErrorAction Stop
 Invoke-CiCommand 'self-test' (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $source 'Relay Server\ci\pipeline\Test-WindowsRunner.ps1'),'-PrivateRoot',$private) $source 120
 if($PolicyFile){$p=Get-Item -LiteralPath $PolicyFile;if($p.PSIsContainer -or $p.Length -gt 65536 -or ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CI_POLICY_FILE_INVALID'};[IO.File]::Copy($p.FullName,(Join-Path $private 'reviewed-policy.json'),$false)}
 Invoke-CiCommand 'snapshot' $node @((Join-Path $source 'Relay Server\ci\evidence\peace.ci-artifacts.js'),'snapshot',$source,$work) $source 120
 Copy-Item -LiteralPath (Join-Path $work 'Relay Server\maintenance\source-manifest.json') -Destination (Join-Path $output 'source-manifest.json')
 Stage 'dependencies' 900
 Stage 'build-inputs' 600
 Stage 'build' 1200
 Stage 'build-inputs-after' 600
 Stage 'normalize' 120
 # Only a new disposable fixture key is used to exercise signature-dependent
 # product code. Neither production private key is ever loaded on this host.
 Stage 'approve' 120
 $results.nativeBuild='PASS';Save-Results
 $probeFailed=$false
 foreach($kind in @('native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare')){try{Stage $kind 600}catch{$probeFailed=$true;break}}
 $results.apiProbe=if($probeFailed){'FAIL'}else{'PASS'};Save-Results
 try {
  Invoke-CiCommand 'integration' (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $work 'Relay Server\ci\pipeline\Integration-Control.ps1'),'-WorkRoot',$work,'-Output',$output,'-PrivateRoot',$private,'-Version',$Version) $work 300
  $details=Read-CiJson (Join-Path $output 'integration-result.json')
  if($details.outcome -ne 'PASS' -or @('ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed').Where({$details[$_] -ne $true}).Count -ne 0){$results.stages.integration.outcome='FAIL';throw 'CI_INTEGRATION_RESULT_INVALID'}
  $results.integration='PASS'
 } catch {$results.integration='FAIL';$results.stages.integration.outcome='FAIL'}
 Save-Results
 # Each enabled cohort starts a fresh private server and real A/B/O execution.
 # Unsupported native observations remain unsupported, not a fabricated pass.
 if($results.integration -eq 'PASS' -and $results.apiProbe -eq 'PASS') {
  $matrix=Read-CiJson (Join-Path $output 'compatibility-observations.json')
  $basePolicy=Read-CiJson (Join-Path $output 'policy.json')
  foreach($mode in @('observe','prohibit')) {
   $candidate=@($matrix.rows|Where-Object{$_.mode -eq $mode -and $_.status -eq 'PASS'})
   if($candidate.Count -ne 2 -or ($basePolicy.dynamicCode -eq 'prohibit' -and $mode -eq 'observe')){continue}
   $name='profile-integration-'+$mode
   try {
    Invoke-CiCommand $name (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $work 'Relay Server\ci\pipeline\Integration-Control.ps1'),'-WorkRoot',$work,'-Output',$output,'-PrivateRoot',$private,'-Version',$Version,'-MitigationMode',$mode) $work 300
    $details=Read-CiJson (Join-Path $output ('integration-profile-'+$mode+'-result.json'))
    if($details.outcome -ne 'PASS' -or $details.mitigationMode -ne $mode -or @($details.profiledAuthorityStages).Count -ne 3 -or @('A','B','O').Where({$details.profiledAuthorityStages -notcontains $_}).Count -ne 0){throw 'CI_PROFILE_INTEGRATION_RESULT_INVALID'}
   } catch {$results.stages[$name].outcome='FAIL';$results.stages[$name].error='CI_PROFILE_INTEGRATION_FAILED'}
   Save-Results
  }
 }
 if($results.apiProbe -eq 'PASS' -and $results.integration -eq 'PASS'){Stage 'security-authority' 1800}
 Stage 'report' 120
 if($results.nativeBuild -eq 'PASS' -and $results.apiProbe -eq 'PASS' -and $results.integration -eq 'PASS' -and $results.stages['security-authority'].outcome -eq 'PASS'){$exit=0}

} catch {
 if($results.stages.build.outcome -eq 'FAIL' -or $results.stages.normalize.outcome -eq 'FAIL' -or $results.stages.approve.outcome -eq 'FAIL'){$results.nativeBuild='FAIL'}
 $results.error=if($_.Exception.Message -match '^CI_[A-Za-z0-9_-]+$'){$_.Exception.Message}else{'CI_RUN_FAILED'}
 Write-Output $results.error
} finally {
 try {
  if($private -and (Test-Path -LiteralPath (Join-Path $private 'ci-owned-marker'))){try{Remove-Item -LiteralPath $private -Recurse -Force}catch{$exit=1;$results.cleanupFailed=$true;Write-Output 'CI_PRIVATE_CLEANUP_FAILED'}}
  try{Save-Results}catch{$exit=1;Write-Output 'CI_RESULTS_WRITE_FAILED'}
 } finally {
  [Environment]::SetEnvironmentVariable('GAME_RELEASE_APPROVAL_KEY_B64',$null)
  [Environment]::SetEnvironmentVariable('GAME_CI_ATTESTATION_KEY_B64',$null)
 }
}
if($exit -eq 0){
 try{
  & $node (Join-Path $source 'Relay Server\ci\evidence\peace.separated-signing.js') seal $output
  if($LASTEXITCODE -ne 0){throw 'CI_UNSIGNED_BUNDLE_SEAL_FAILED'}
  Write-Output 'CI_UNSIGNED_TEST_BUNDLE_READY: isolated fixture approvals are NOT production approvals.'
 }catch{$exit=1;Write-Output 'CI_UNSIGNED_BUNDLE_SEAL_FAILED'}
}
Write-Output ('CI_RESULTS '+($results|ConvertTo-Json -Depth 8 -Compress))
exit $exit
