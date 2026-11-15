param(
 [string]$SourceRoot=(Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),
 [string]$ResultsDirectory=(Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'tools\runtime'),
 [string]$BdsRoot=$env:BDS
)
# Compiled TEST probes only. No product A/B/O build, GPU acceptance or production signing.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$private=$null;$output=$null;$logs=$null;$exit=1;$active=$null;$createdResult=$false
$names=@('snapshot','compile-probes','sdk-probe','abi-compare','Cozy.HardeningContractsProbe','Cozy.TlsPinWindowProbe','Cozy.TlsContractProbe','Cozy.HashContracts','Cozy.IntegrityHashProbe','Cozy.CrcProbe','Cozy.ServerPolicyLocalProbe','Cozy.ProcessMitigationProfileProbe','Cozy.NativeApiContractsProbe','Cozy.MeasurementLifetimeProbe','Cozy.JsonEnvelopeProbe','Cozy.ThreadInventoryProbe','Cozy.Blake3ParallelProbe','Cozy.HandoffKdfProbe','Cozy.ServerOperationsProtocolProbe','Cozy.PointerGraphProbe','pe-corpus','native-hash-compare')
$result=[ordered]@{version=1;scope='NATIVE_TEST_CONTRACTS_6_TO_10';windowsExecuted=$false;outcome='NOT_RUN';productBuild='NOT_RUN';productIntegration='NOT_RUN';stages=[ordered]@{}}
foreach($name in $names){$result.stages[$name]=[ordered]@{outcome='NOT_RUN';exitCode=$null;elapsedMs=0}}
function Save-ContractResults {
 if($createdResult){[IO.File]::WriteAllText($output,($result|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))}
}
function Invoke-ContractCommand([string]$Name,[string]$Exe,[string[]]$Arguments,[string]$Directory,[int]$Seconds){
 $entry=$result.stages[$Name];$watch=[Diagnostics.Stopwatch]::StartNew();$job=$null
 $log=Join-Path $logs ($Name+'.log');$entry.log=[IO.Path]::GetFileName($logs)+'/'+$Name+'.log'
 try{
  $job=[GameWindowsTests.WindowsJob]::Start($Exe,$Arguments,$Directory,(Get-TestEnvironment $private),$log)
  $result.windowsExecuted=$true
  $result.osVersion=[Environment]::OSVersion.VersionString
  $result.gpuCompatibility='NOT_RUN_BY_THIS_PROBE_RUNNER'
  $result.actualProductTlsHandshake='NOT_RUN_BY_THIS_PROBE_RUNNER'
  while(-not $job.HasExited){
   if($watch.Elapsed.TotalSeconds -gt $Seconds){throw 'NATIVE_CONTRACT_TIMEOUT'}
   if((Get-Item -LiteralPath $log).Length -gt 8MB){throw 'NATIVE_CONTRACT_LOG_LIMIT'}
   Start-Sleep -Milliseconds 100
  }
  $entry.exitCode=[int64]$job.ExitCode
  if($entry.exitCode -ne 0){throw 'NATIVE_CONTRACT_NONZERO_EXIT'}
  $drain=[Diagnostics.Stopwatch]::StartNew()
  while(@($job.ProcessIds()).Count -gt 0 -and $drain.Elapsed.TotalSeconds -lt 2){Start-Sleep -Milliseconds 50}
  if(@($job.ProcessIds()).Count -gt 0){throw 'NATIVE_CONTRACT_CHILD_REMAINS'}
  $entry.outcome='PASS'
 }catch{
  $entry.outcome='FAIL';$entry.error=if($_.Exception.Message -match '^(?:NATIVE_CONTRACT|WINDOWS_TEST)_[A-Z0-9_]+$'){$_.Exception.Message}else{'NATIVE_CONTRACT_EXECUTION_FAILED'}
  throw
 }finally{
  if($job){try{$job.Dispose()}catch{$entry.outcome='FAIL';$entry.error='NATIVE_CONTRACT_CLEANUP_FAILED';$result.outcome='FAIL';$script:exit=1}}
  $entry.elapsedMs=[int64]$watch.ElapsedMilliseconds
  if(Test-Path -LiteralPath $log){$entry.sha512=(Get-FileHash -LiteralPath $log -Algorithm SHA512).Hash.ToLowerInvariant()}
  Save-ContractResults
  if($entry.outcome -ne 'PASS'){throw 'NATIVE_CONTRACT_STAGE_FAILED'}
 }
}
try{
 $parent=(Resolve-Path -LiteralPath $ResultsDirectory).ProviderPath
 $id=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,12)
 $output=Join-Path $parent ('native-contracts-6-10-'+$id+'.json')
 $stream=[IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$stream.Dispose();$createdResult=$true;Save-ContractResults
 # WindowsCommon rejects non-Windows / non-x64 / pre-7 PowerShell before native work.
 . (Join-Path $PSScriptRoot 'WindowsCommon.ps1')
 if(-not $BdsRoot -or $BdsRoot -match '[%&|<>^!"\r\n]' -or -not(Test-Path -LiteralPath (Join-Path $BdsRoot 'bin\dcc64.exe'))){throw 'NATIVE_CONTRACT_RAD_STUDIO_REQUIRED'}
 $env:BDS=(Resolve-Path -LiteralPath $BdsRoot).ProviderPath
 $source=(Resolve-Path -LiteralPath $SourceRoot).ProviderPath
 $node=(Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
 $null=Get-Command cl.exe -CommandType Application -ErrorAction Stop
 $logs=Join-Path $parent ('native-contracts-6-10-'+$id+'-logs');New-TestPrivateDirectory $logs
 $private=Join-Path ([IO.Path]::GetTempPath()) ('GameNativeContracts6To10-'+[Guid]::NewGuid().ToString('N'));New-TestPrivateDirectory $private
 if($private -match '[%&|<>^!"\r\n]'){throw 'NATIVE_CONTRACT_PATH_INVALID'}
 $work=Join-Path $private 'source'
 Invoke-ContractCommand 'snapshot' $node @((Join-Path $source 'Relay Server\tools\build\peace.source-snapshot.js'),'snapshot',$source,$work) $source 120
 $native=Join-Path $work 'Railway'
 # Existing per-probe DCU isolation is kept. The build-only step compiles the
 # full existing probe set, but only the named 6-10 probes below are executed.
 Invoke-ContractCommand 'compile-probes' $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'Cozy.Tests\Cozy.Build\Cozy.Build_NativeProbes_Win64.bat')+'" /build-only')) $native 900
 Invoke-ContractCommand 'sdk-probe' $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'Cozy.Tests\Cozy.Platform\Cozy.Build_NativeAbi_SDK_Win64.bat')+'"')) $native 180
 $built=Join-Path $native 'build\tests\native-probes'
 Invoke-ContractCommand 'abi-compare' $node @((Join-Path $native 'Cozy.Tests\Cozy.Platform\Cozy.compare-native-abi.js'),(Join-Path $built 'Cozy.NativeAbiProbe.exe'),(Join-Path $native 'build\tests\native-sdk\Cozy.NativeAbiSdkProbe.exe')) $native 60
 foreach($name in $names[4..($names.Count-3)]){Invoke-ContractCommand $name (Join-Path $built ($name+'.exe')) @() $native 120}
 Invoke-ContractCommand 'native-hash-compare' $node @((Join-Path $work 'Relay Server\tests\cryptography\peace.compare-native-hashes.js'),'--hash-probe',(Join-Path $built 'Cozy.IntegrityHashProbe.exe'),'--crc-probe',(Join-Path $built 'Cozy.CrcProbe.exe'),'--mode-probe',(Join-Path $built 'Cozy.HashProbe.exe'),'--pe-probe',(Join-Path $built 'Cozy.PeCorpusProbe.exe'),'--crc-pe-probe',(Join-Path $built 'Cozy.CrcPeProbe.exe')) $native 900
 Invoke-ContractCommand 'pe-corpus' $node @((Join-Path $work 'Relay Server\tests\artifacts\peace.test-hardening-pe-corpus.js'),'--native',(Join-Path $built 'Cozy.PeCorpusProbe.exe')) $native 180
 if(Select-String -LiteralPath (Join-Path $logs 'Cozy.HardeningContractsProbe.log') -Pattern '(?i)\bSKIP\b' -Quiet){$result.stages['Cozy.HardeningContractsProbe'].outcome='PARTIAL_PRIVILEGE_SKIP';throw 'NATIVE_CONTRACT_REQUIRED_BRANCH_SKIPPED'}
 if(@($result.stages.Values | Where-Object {$_.outcome -ne 'PASS'}).Count -ne 0){throw 'NATIVE_CONTRACT_RESULTS_INCOMPLETE'}
 $result.outcome='PASS';$exit=0
}catch{
 $result.outcome=if($result.windowsExecuted){'FAIL'}else{'BLOCKED_PREREQUISITE'}
 $result.error=if($_.Exception.Message -match '^(?:WINDOWS_TEST|NATIVE_CONTRACT)_[A-Za-z0-9_]+$'){$_.Exception.Message}else{'NATIVE_CONTRACT_PREREQUISITE_OR_RUN_FAILED'}
 Write-Output $result.error
}finally{
 if($private -and (Test-Path -LiteralPath (Join-Path $private 'test-owned-marker'))){try{Remove-Item -LiteralPath $private -Recurse -Force}catch{$result.outcome='FAIL';$result.cleanupFailed=$true;$exit=1}}
 $result.finishedAt=[DateTime]::UtcNow.ToString('o')
 try{Save-ContractResults}catch{$exit=1;Write-Output 'NATIVE_CONTRACT_RESULT_WRITE_FAILED'}
}
if($output){Write-Output ('NATIVE_CONTRACT_RESULTS '+$output)}
exit $exit
