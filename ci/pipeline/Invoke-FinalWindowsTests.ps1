param(
 [string]$SourceRoot=(Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),
 [Parameter(Mandatory)][string]$AFile,[Parameter(Mandatory)][string]$BFile,[Parameter(Mandatory)][string]$OFile,
 [Parameter(Mandatory)][string]$PackingReceiptsFile,[Parameter(Mandatory)][string]$PolicyFile,
 [string]$ServerPoliciesFile,
 [Parameter(Mandatory)][ValidatePattern('^\d+(?:\.\d+){0,3}$')][string]$Version,
 [Parameter(Mandatory)][string]$ResultFile
)
# Run final files as supplied. Never claim this run compiled them; never publish,
# generate production approvals, use production DATA_DIR or retain test keys.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$private=$null;$target=$null;$node=$null;$exit=1
$result=[ordered]@{version=1;kind='FINAL_WINDOWS_EXECUTION_OBSERVATION_NOT_CI_ATTESTATION';outcome='FAIL';finalExecutionOnly=$true;buildProvenance='NOT_ATTESTED';productionApproved=$false;finalExecutionVerified=$false;integrationAttempted=$false;receiptAuthenticity='OPERATOR_SUPPLIED_NOT_INDEPENDENTLY_ATTESTED';releaseVersion=$Version;artifacts=@{};stages=[ordered]@{};cleanup='NOT_RUN';secretBoundary='NOT_RUN'}
function Assert-ResultParent([string]$File) {
 $parent=[IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($File))
 while($null -ne $parent){
  $parent.Refresh()
  if(-not $parent.Exists){throw 'CI_FINAL_RESULT_PARENT_REQUIRED'}
  if(($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'CI_FINAL_RESULT_REPARSE_FORBIDDEN'}
  $parent=$parent.Parent
 }
}
function Run-Observed([string]$Name,[string]$Exe,[string[]]$Arguments,[string]$Directory,[int]$Seconds,[int[]]$Allowed=@(0)) {
 $job=$null;$watch=[Diagnostics.Stopwatch]::StartNew();$record=@{outcome='FAIL';exitCode=$null;elapsedMs=0};$result.stages[$Name]=$record
 try {
  $log=Join-Path $private ($Name+'.log')
  $job=[GameCi.WindowsJob]::Start($Exe,$Arguments,$Directory,(Get-CiEnvironment $private),$log)
  while(-not $job.HasExited){if($watch.Elapsed.TotalSeconds -gt $Seconds){throw 'CI_FINAL_STAGE_TIMEOUT'};if((Get-Item -LiteralPath $log).Length -gt 64MB){throw 'CI_FINAL_LOG_LIMIT'};Start-Sleep -Milliseconds 100}
  $record.exitCode=[int]$job.ExitCode;if($Allowed -notcontains $record.exitCode){throw 'CI_FINAL_STAGE_FAILED'}
  $drain=[Diagnostics.Stopwatch]::StartNew();while(@($job.ProcessIds()).Count -ne 0 -and $drain.Elapsed.TotalSeconds -lt 2){Start-Sleep -Milliseconds 50}
  if(@($job.ProcessIds()).Count -ne 0){throw 'CI_FINAL_ORPHAN_PROCESS'}
  $record.outcome='PASS';return $record.exitCode
 }finally{$record.elapsedMs=[int64]$watch.ElapsedMilliseconds;if($job){try{$job.Dispose()}catch{$record.outcome='FAIL';throw 'CI_FINAL_JOB_CLEANUP_FAILED'}}}
}
try {
 $source=[IO.Path]::GetFullPath($SourceRoot).TrimEnd([char[]]@('\','/'))
 $candidate=[IO.Path]::GetFullPath($ResultFile)
 if(Test-Path -LiteralPath $candidate){throw 'CI_FINAL_NEW_RESULT_REQUIRED'}
 if($candidate.StartsWith($source+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'CI_FINAL_RESULT_OUTSIDE_SOURCE_REQUIRED'}
 Assert-ResultParent $candidate
 $target=$candidate
 . (Join-Path $PSScriptRoot 'CiCommon.ps1')
 if(-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0){throw 'CI_FINAL_INTERACTIVE_WINDOWS_REQUIRED'}
 if($env:GAME_RELEASE_APPROVAL_KEY_B64 -or $env:GAME_CI_ATTESTATION_KEY_B64){throw 'CI_FINAL_PRODUCTION_KEYS_FORBIDDEN'}
 $node=(Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 $private=Join-Path ([IO.Path]::GetTempPath()) ('CozyFinalWindows-'+[Guid]::NewGuid().ToString('N'));New-CiPrivateDirectory $private
 $work=Join-Path $private 'source';$web=Join-Path $work 'Relay Server';$bundle=Join-Path $private 'final-files'
 $null=Run-Observed 'snapshot' $node @((Join-Path $source 'Relay Server\ci\evidence\peace.ci-artifacts.js'),'snapshot',$source,$work) $source 120
 $npm=(Get-Command npm.cmd -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 $null=Run-Observed 'dependencies' $env:ComSpec @('/d','/c',('"'+$npm+'" ci --engine-strict --ignore-scripts --no-audit --no-fund')) $web 900
 $inputFile=Join-Path $private 'selected-inputs.json'
 $selectedInputs=@{version=1;releaseVersion=$Version;artifacts=@{A=[IO.Path]::GetFullPath($AFile);B=[IO.Path]::GetFullPath($BFile);O=[IO.Path]::GetFullPath($OFile)};packingReceiptsFile=[IO.Path]::GetFullPath($PackingReceiptsFile);policyFile=[IO.Path]::GetFullPath($PolicyFile)}
 if($ServerPoliciesFile){$selectedInputs.serverPoliciesFile=[IO.Path]::GetFullPath($ServerPoliciesFile)}
 Write-CiJson $inputFile $selectedInputs
 $helper=Join-Path $web 'ci\pipeline\peace.final-windows-inputs.js'
 $null=Run-Observed 'prepare' $node @($helper,'prepare',$inputFile,$work,$bundle) $web 120
 $input=Read-CiJson (Join-Path $bundle 'final-execution-inputs.json')
 $result.artifacts=$input.artifacts;$result.sourceManifestSha512=$input.sourceManifestSha512;$result.reviewedPolicySha512=$input.reviewedPolicySha512
 if($input.ContainsKey('protectionEngine')){$result.protectionEngine=$input.protectionEngine;$result.fixtureEnrollmentApproval=$input.fixtureEnrollmentApproval;$result.serverPolicyAuthenticity=$input.serverPolicyAuthenticity}
 $secretExit=Run-Observed 'client-secrets' $node @((Join-Path $web 'tools\security\peace.audit-client-secrets.js'),(Join-Path $bundle 'A.exe'),(Join-Path $bundle 'B.exe'),(Join-Path $bundle 'O.exe')) $web 120 @(0,1)
 $secret=Read-CiJson (Join-Path $private 'client-secrets.log')
 if($secret.kind -ne 'CLIENT_STATIC_SECRET_CHECK' -or ($secretExit -eq 0 -and $secret.status -ne 'PASS') -or ($secretExit -eq 1 -and $secret.status -ne 'BLOCKED')){throw 'CI_FINAL_SECRET_REPORT_INVALID'}
 if(@($secret.artifacts).Count -ne 3 -or $secret.guaranteesAbsenceOfSecrets -ne $false){throw 'CI_FINAL_SECRET_REPORT_INVALID'}
 foreach($role in @('A','B','O')){
  $row=@($secret.artifacts|Where-Object{$_.role -eq $role})
  if($row.Count -ne 1 -or $row[0].sha512 -ne $input.artifacts[$role].sha512 -or $row[0].size -ne $input.artifacts[$role].size){throw 'CI_FINAL_SECRET_REPORT_FILE_MISMATCH'}
 }
 $result.secretScanGuaranteesAbsenceOfSecrets=$false
 $result.secretBoundary=$secret.status;$result.stages['client-secrets'].outcome=$secret.status
 # Execution observation is separate from key-free release eligibility. A V1
 # file may run successfully while its embedded key keeps the result BLOCKED.
 $result.integrationAttempted=$true
 $null=Run-Observed 'integration' (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $web 'ci\pipeline\Integration-Control.ps1'),'-WorkRoot',$work,'-Output',$bundle,'-PrivateRoot',$private,'-Version',$Version) $work 300
 $integration=Read-CiJson (Join-Path $bundle 'integration-result.json')
 if($integration.outcome -ne 'PASS' -or @('ready','licenseConsumed','overlayFirstFrame','parentTransferred','parentExited','parentFilesDeleted','overlayClosed','serverSessionClosed','fixtureClaimObservationBarrierUsed').Where({$integration[$_] -ne $true}).Count -ne 0){throw 'CI_FINAL_INTEGRATION_INCOMPLETE'}
 $result.fixtureClaimObservationBarrierUsed=$true
 if($input.ContainsKey('protectionEngine') -and $input.protectionEngine -eq 'COZY_SERVER_POLICY_V2'){
  if($integration.fixtureEnrollmentApprovalUsed -ne $true){throw 'CI_FINAL_FIXTURE_APPROVAL_INCOMPLETE'}
  $result.fixtureEnrollmentApprovalUsed=$true
 }
 $null=Run-Observed 'verify' $node @($helper,'verify',$bundle) $web 120
 $result.finalExecutionVerified=$true;$result.integration='PASS';$result.outcome=if($result.secretBoundary -eq 'PASS'){'PASS'}else{'BLOCKED'};$exit=if($result.outcome -eq 'PASS'){0}else{2}
}catch{
 $result.outcome='FAIL';$result.error=if($_.Exception.Message -cmatch '^CI_[A-Z0-9_]+$'){$_.Exception.Message}else{'CI_FINAL_RUN_FAILED'}
}finally{
 if($private -and (Test-Path -LiteralPath (Join-Path $private 'ci-owned-marker'))){try{Remove-Item -LiteralPath $private -Recurse -Force;$result.cleanup='PASS'}catch{$result.cleanup='FAIL';$result.outcome='FAIL';$result.error='CI_FINAL_PRIVATE_CLEANUP_FAILED';$exit=1}}
 if($target){try{Assert-ResultParent $target;$stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 12));$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}}catch{$exit=1;$result.outcome='FAIL';$result.error='CI_FINAL_RESULT_WRITE_FAILED';Write-Output 'CI_FINAL_RESULT_WRITE_FAILED'}}
}
Write-Output ($result|ConvertTo-Json -Depth 12 -Compress)
exit $exit
