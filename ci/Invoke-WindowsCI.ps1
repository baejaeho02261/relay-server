param(
 [string]$SourceRoot=(Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
 [Parameter(Mandatory)][string]$OutputDirectory,
 [Parameter(Mandatory)][ValidatePattern('^\d+(?:\.\d+){0,3}$')][string]$Version,
 [ValidateRange(1,2147483647)][int]$SecurityVersion=1,
 [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]{1,100}$')][string]$RunId,
 [string]$BdsRoot=$env:BDS,[string]$ReleaseKeyFile,[string]$CiKeyFile,[string]$PolicyFile
)
# All outputs are observations of actual subprocesses, never operator PASS input.
. (Join-Path $PSScriptRoot 'CiCommon.ps1')
$private=$null;$output=$null;$work=$null;$exit=1;$active=$null
$results=@{version=1;runId=$RunId;windowsExecuted=$true;stages=[ordered]@{};nativeBuild='NOT_RUN';apiProbe='NOT_RUN';integration='NOT_RUN';signed=$false}
foreach($name in @('self-test','snapshot','dependencies','build','normalize','approve','native-probes','sdk-probe','abi-compare','integration','report','sign')){$results.stages[$name]=@{outcome='NOT_RUN';exitCode=$null;elapsedMs=0}}
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
  $record.error=if($_.Exception.Message -match '^CI_[A-Z0-9_]+$'){$_.Exception.Message}else{'CI_STAGE_EXCEPTION'}
  throw "CI_STAGE_FAILED_$Name"
 } finally {$cleanupFailed=$false;if($job){try{$job.Dispose()}catch{$record.outcome='FAIL';$record.error='CI_JOB_CLEANUP_FAILED';$cleanupFailed=$true}};$record.elapsedMs=[int64]$watch.Elapsed.TotalMilliseconds;Save-Results;if($cleanupFailed){throw 'CI_JOB_CLEANUP_FAILED'}}
}
function Stage([string]$Kind,[int]$Seconds=600,[string]$Key='') {
 $stageArgs=@('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $work 'GameWeb\ci\Windows-Stage.ps1'),'-Kind',$Kind,'-WorkRoot',$work,'-Output',$output,'-Version',$Version,'-SecurityVersion',[string]$SecurityVersion,'-RunId',$RunId)
 if($Key){$stageArgs+=@('-KeyFile',$Key)}
 if($Kind -eq 'approve' -and $PolicyFile){$stageArgs+=@('-PolicyFile',(Join-Path $private 'reviewed-policy.json'))}
 Invoke-CiCommand $Kind (Join-Path $PSHOME 'pwsh.exe') $stageArgs $work $Seconds
}
function Copy-CiKey([string]$File,[string]$Variable,[string]$Name) {
 $target=Join-Path $private $Name
 if($File){$fileInfo=Get-Item -LiteralPath $File;if($fileInfo.PSIsContainer -or $fileInfo.Length -gt 16384 -or ($fileInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CI_KEY_FILE_INVALID'};[IO.File]::Copy($fileInfo.FullName,$target,$false)}
 else {
  $text=[Environment]::GetEnvironmentVariable($Variable)
  if(-not $text -or $text.Length -gt 24000){throw 'CI_SIGNING_KEYS_REQUIRED'}
  $bytes=[Convert]::FromBase64String($text)
  try {[IO.File]::WriteAllBytes($target,$bytes)}finally{[Array]::Clear($bytes,0,$bytes.Length);[Environment]::SetEnvironmentVariable($Variable,$null)}
 }
 return $target
}
try {
 if(-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'CI_INTERACTIVE_RUNNER_REQUIRED'}
 if(-not $BdsRoot -or -not(Test-Path -LiteralPath (Join-Path $BdsRoot 'bin\dcc64.exe'))){throw 'CI_RAD_STUDIO_REQUIRED'}
 $env:BDS=(Resolve-Path -LiteralPath $BdsRoot).ProviderPath
 $source=(Resolve-Path -LiteralPath $SourceRoot).ProviderPath
 $output=[IO.Path]::GetFullPath($OutputDirectory);New-CiPrivateDirectory $output
 [IO.Directory]::CreateDirectory((Join-Path $output 'logs'))|Out-Null
 $private=Join-Path ([IO.Path]::GetTempPath()) ('GameWindowsCI-'+[Guid]::NewGuid().ToString('N'));New-CiPrivateDirectory $private
 $work=Join-Path $private 'source';$node=(Get-Command node.exe -CommandType Application -ErrorAction Stop).Source
 $null=Get-Command openssl.exe -CommandType Application -ErrorAction Stop
 $null=Get-Command cl.exe -CommandType Application -ErrorAction Stop
 Invoke-CiCommand 'self-test' (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $source 'GameWeb\ci\Test-WindowsRunner.ps1'),'-PrivateRoot',$private) $source 120
 if($PolicyFile){$p=Get-Item -LiteralPath $PolicyFile;if($p.PSIsContainer -or $p.Length -gt 65536 -or ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CI_POLICY_FILE_INVALID'};[IO.File]::Copy($p.FullName,(Join-Path $private 'reviewed-policy.json'),$false)}
 Invoke-CiCommand 'snapshot' $node @((Join-Path $source 'GameWeb\ci\ci-artifacts.js'),'snapshot',$source,$work) $source 120
 Copy-Item -LiteralPath (Join-Path $work 'GameWeb\maintenance\source-manifest.json') -Destination (Join-Path $output 'source-manifest.json')
 Stage 'dependencies' 900
 Stage 'build' 1200
 Stage 'normalize' 120
 # Keys are materialized only after source verification and a successful clean
 # native build. Child environments never inherit CI tokens/secrets.
 $releaseKey=Copy-CiKey $ReleaseKeyFile 'GAME_RELEASE_APPROVAL_KEY_B64' 'release-approval.pem'
 $ciKey=Copy-CiKey $CiKeyFile 'GAME_CI_ATTESTATION_KEY_B64' 'ci-attestation.pem'
 Stage 'approve' 120 $releaseKey
 $results.nativeBuild='PASS';Save-Results
 $probeFailed=$false
 foreach($kind in @('native-probes','sdk-probe','abi-compare')){try{Stage $kind 600}catch{$probeFailed=$true;break}}
 $results.apiProbe=if($probeFailed){'FAIL'}else{'PASS'};Save-Results
 try {
  Invoke-CiCommand 'integration' (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $work 'GameWeb\ci\Integration-Control.ps1'),'-WorkRoot',$work,'-Output',$output,'-PrivateRoot',$private,'-Version',$Version) $work 300
  $details=Read-CiJson (Join-Path $output 'integration-result.json')
  if($details.outcome -ne 'PASS' -or @('ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed').Where({$details[$_] -ne $true}).Count -ne 0){$results.stages.integration.outcome='FAIL';throw 'CI_INTEGRATION_RESULT_INVALID'}
  $results.integration='PASS'
 } catch {$results.integration='FAIL';$results.stages.integration.outcome='FAIL'}
 Save-Results
 Stage 'report' 120
 Stage 'sign' 120 $ciKey
 $results.signed=$true
 if($results.nativeBuild -eq 'PASS' -and $results.apiProbe -eq 'PASS' -and $results.integration -eq 'PASS'){$exit=0}
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
Write-Output ('CI_RESULTS '+($results|ConvertTo-Json -Depth 8 -Compress))
exit $exit
