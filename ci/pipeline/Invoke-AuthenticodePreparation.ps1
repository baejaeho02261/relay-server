param(
 [Parameter(Mandatory)][string]$AFile,[Parameter(Mandatory)][string]$BFile,[Parameter(Mandatory)][string]$OFile,
 [Parameter(Mandatory)][string]$SignTool,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{128}$')][string]$SignToolSha512,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{128}$')][string]$NodeSha512,
 [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$CertificateSha256,
 [ValidateSet('CurrentUser','LocalMachine')][string]$CertificateStore='CurrentUser',
 [Parameter(Mandatory)][string]$TimestampUri,
 [Parameter(Mandatory)][string]$OutputDirectory
)
# Signing preparation only. The private key remains with the Windows certificate
# provider; no PFX/password/private-key file is accepted. The resulting bytes need
# fresh Windows tests, detached approval and a matching publication manifest.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$private=$null;$privateCreated=$false;$privateCreatedAt=0;$published=$false;$exit=1;$nodeLock=$null;$signerLock=$null
$result=[ordered]@{version=1;kind='AUTHENTICODE_PREPARATION_NOT_RELEASE_APPROVAL';outcome='FAIL';signatureVerification='NOT_RUN';windowsProductExecuted=$false;productionApproved=$false;publicationPerformed=$false;privateKeyExported=$false;cleanup='NOT_RUN';artifacts=@{}}
function Assert-LocalPath([string]$Value,[bool]$Directory) {
 if(-not [IO.Path]::IsPathFullyQualified($Value) -or $Value.StartsWith('\\') -or $Value.Contains([char]0)){throw 'CI_AUTHENTICODE_LOCAL_PATH_REQUIRED'}
 $file=[IO.Path]::GetFullPath($Value)
 $item=Get-Item -LiteralPath $file -Force -ErrorAction Stop
 if([bool]$item.PSIsContainer -ne $Directory){throw 'CI_AUTHENTICODE_PATH_TYPE_INVALID'}
 $cursor=$item
 while($null -ne $cursor){
  if(($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'CI_AUTHENTICODE_REPARSE_FORBIDDEN'}
  $cursor=if($cursor -is [IO.DirectoryInfo]){$cursor.Parent}else{$cursor.Directory}
 }
 return $file
}
function Read-Hash([string]$File){return (Get-FileHash -LiteralPath $File -Algorithm SHA512).Hash.ToLowerInvariant()}
function Certificate-Hash($Certificate){
 $hash=[Security.Cryptography.SHA256]::Create()
 try{return [BitConverter]::ToString($hash.ComputeHash($Certificate.RawData)).Replace('-','')}finally{$hash.Dispose()}
}
function Set-PrivateAcl([string]$Directory){
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 foreach($who in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($who,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
 Set-Acl -LiteralPath $Directory -AclObject $acl
}
function Run-Owned([string]$Name,[string]$Executable,[string[]]$Arguments,[int]$Seconds) {
 $job=$null;$watch=[Diagnostics.Stopwatch]::StartNew();$log=Join-Path $private ($Name+'.log')
 try{
  $job=[GameCi.WindowsJob]::Start($Executable,$Arguments,$private,(Get-CiEnvironment $private),$log)
  while(-not $job.HasExited){
   if($watch.Elapsed.TotalSeconds -gt $Seconds){throw 'CI_AUTHENTICODE_STAGE_TIMEOUT'}
   if((Get-Item -LiteralPath $log).Length -gt 8MB){throw 'CI_AUTHENTICODE_LOG_LIMIT'}
   Start-Sleep -Milliseconds 100
  }
  if([int]$job.ExitCode -ne 0){throw 'CI_AUTHENTICODE_STAGE_FAILED'}
  $drain=[Diagnostics.Stopwatch]::StartNew()
  while(@($job.ProcessIds()).Count -ne 0 -and $drain.Elapsed.TotalSeconds -lt 2){Start-Sleep -Milliseconds 50}
  if(@($job.ProcessIds()).Count -ne 0){throw 'CI_AUTHENTICODE_ORPHAN_PROCESS'}
  return $log
 }finally{if($job){$job.Dispose()}}
}
try{
 . (Join-Path $PSScriptRoot 'CiCommon.ps1')
 if(-not ('CozySigning.AtomicDirectory' -as [type])){
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CozySigning { public static class AtomicDirectory {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool CreateDirectoryW(string path, IntPtr securityAttributes);
} }
'@
 }
 $relay=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
 $destination=[IO.Path]::GetFullPath($OutputDirectory)
 if(Test-Path -LiteralPath $destination){throw 'CI_AUTHENTICODE_NEW_OUTPUT_REQUIRED'}
 $destinationParent=Assert-LocalPath ([IO.Path]::GetDirectoryName($destination)) $true
 if($destination.StartsWith($relay+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'CI_AUTHENTICODE_OUTPUT_OUTSIDE_SOURCE_REQUIRED'}
 $timestamp=[Uri]::new($TimestampUri,[UriKind]::Absolute)
 if($timestamp.Scheme -ne 'https' -or $timestamp.UserInfo -or $timestamp.Fragment -or $timestamp.Query){throw 'CI_AUTHENTICODE_HTTPS_TIMESTAMP_REQUIRED'}
 $signer=Assert-LocalPath $SignTool $false
 $signerLock=[IO.File]::Open($signer,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if((Read-Hash $signer) -cne $SignToolSha512.ToLowerInvariant()){throw 'CI_AUTHENTICODE_SIGNTOOL_HASH_MISMATCH'}
 $node=(Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 $node=Assert-LocalPath $node $false
 $nodeLock=[IO.File]::Open($node,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 if((Read-Hash $node) -cne $NodeSha512.ToLowerInvariant()){throw 'CI_AUTHENTICODE_NODE_HASH_MISMATCH'}
 # Same volume as the final destination makes the final rename atomic. Native
 # CreateDirectory fails for an existing path, so cleanup never claims one.
 $private=Join-Path $destinationParent ('.CozyAuthenticode-'+[Guid]::NewGuid().ToString('N'))
 if(-not [CozySigning.AtomicDirectory]::CreateDirectoryW($private,[IntPtr]::Zero)){throw 'CI_AUTHENTICODE_PRIVATE_CREATE_FAILED'}
 $privateCreated=$true;$privateCreatedAt=(Get-Item -LiteralPath $private -Force).CreationTimeUtc.Ticks
 Set-PrivateAcl $private
 [IO.File]::WriteAllText((Join-Path $private 'ci-owned-marker'),'COZY_AUTHENTICODE_PREPARATION_V1')
 $expectedNode=(Get-Content -LiteralPath (Join-Path $relay 'package.json') -Raw|ConvertFrom-Json).engines.node
 $versionLog=Run-Owned 'node-version' $node @('-p','process.versions.node') 15
 $actualNode=(Get-Content -LiteralPath $versionLog -Raw).Trim()
 if($actualNode -cne $expectedNode){throw 'CI_AUTHENTICODE_LOCKED_NODE_REQUIRED'}
 $certificates=@(Get-ChildItem -LiteralPath ('Cert:\'+$CertificateStore+'\My') | Where-Object {
  (Certificate-Hash $_) -ceq $CertificateSha256.ToUpperInvariant()
 })
 if($certificates.Count -ne 1){throw 'CI_AUTHENTICODE_CERTIFICATE_REQUIRED'}
 $certificate=$certificates[0]
 if(-not $certificate.HasPrivateKey -or $certificate.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or $certificate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow){throw 'CI_AUTHENTICODE_CERTIFICATE_NOT_USABLE'}
 if(@($certificate.EnhancedKeyUsageList|Where-Object{$_.ObjectId -eq '1.3.6.1.5.5.7.3.3'}).Count -ne 1){throw 'CI_AUTHENTICODE_CODE_SIGNING_EKU_REQUIRED'}
 $unsigned=Join-Path $private 'unsigned';$signed=Join-Path $private 'signed'
 $null=[IO.Directory]::CreateDirectory($unsigned);$null=[IO.Directory]::CreateDirectory($signed)
 $files=@{A=$AFile;B=$BFile;O=$OFile};$inputs=@{};$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 $helper=Join-Path $PSScriptRoot 'peace.authenticode-plan.js'
 foreach($role in @('A','B','O')){
  $source=Assert-LocalPath $files[$role] $false
  if(-not $seen.Add($source)){throw 'CI_AUTHENTICODE_DISTINCT_INPUTS_REQUIRED'}
  $log=Run-Owned ('inspect-'+$role) $node @($helper,'inspect',$source,$role) 60
  $observation=Read-CiJson $log
  if($observation.role -cne $role -or $observation.clientSecretScan -ne 'PASS'){throw 'CI_AUTHENTICODE_INPUT_CHECK_FAILED'}
  $input=Join-Path $unsigned ($role+'.exe');$output=Join-Path $signed ($role+'.exe')
  [IO.File]::Copy($source,$input,$false);[IO.File]::Copy($input,$output,$false)
  if((Read-Hash $input) -cne $observation.sha512 -or (Read-Hash $source) -cne $observation.sha512){throw 'CI_AUTHENTICODE_INPUT_CHANGED'}
  $inputs[$role]=@{source=$source;sha512=$observation.sha512}
 }
 foreach($role in @('A','B','O')){
  $input=Join-Path $unsigned ($role+'.exe');$output=Join-Path $signed ($role+'.exe')
  $null=Assert-LocalPath $signer $false
  if((Read-Hash $signer) -cne $SignToolSha512.ToLowerInvariant()){throw 'CI_AUTHENTICODE_SIGNTOOL_HASH_MISMATCH'}
  $arguments=@('sign','/q','/s','My','/sha1',$certificate.Thumbprint,'/fd','SHA256','/tr',$timestamp.AbsoluteUri,'/td','SHA256')
  if($CertificateStore -eq 'LocalMachine'){$arguments+='/sm'}
  $arguments+=$output
  $null=Run-Owned ('sign-'+$role) $signer $arguments 180
  $signatureLock=[IO.File]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{
   $verifiedHash=Read-Hash $output
   $null=Run-Owned ('verify-'+$role) $signer @('verify','/q','/pa','/all','/tw',$output) 120
   $signature=Get-AuthenticodeSignature -LiteralPath $output
   if($signature.Status -ne 'Valid' -or [string]$signature.SignatureType -ne 'Authenticode' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate){throw 'CI_AUTHENTICODE_SIGNATURE_INVALID'}
   $signingHash=Certificate-Hash $signature.SignerCertificate
   if($signingHash -cne $CertificateSha256.ToUpperInvariant()){throw 'CI_AUTHENTICODE_SIGNER_MISMATCH'}
   $log=Run-Owned ('lineage-'+$role) $node @($helper,'compare',$input,$output,$role) 60
   $lineage=Read-CiJson $log
   if($lineage.role -cne $role -or -not $lineage.onlySignatureMetadataChanged -or $lineage.inputSha512 -cne $inputs[$role].sha512 -or $lineage.outputSha512 -cne $verifiedHash -or (Read-Hash $output) -cne $verifiedHash){throw 'CI_AUTHENTICODE_LINEAGE_INVALID'}
   $lineage.signatureCryptographicallyVerified=$true
   $result.artifacts[$role]=$lineage
  }finally{$signatureLock.Dispose()}
 }
 foreach($role in @('A','B','O')){
  if((Read-Hash $inputs[$role].source) -cne $inputs[$role].sha512 -or (Read-Hash (Join-Path $signed ($role+'.exe'))) -cne $result.artifacts[$role].outputSha512){throw 'CI_AUTHENTICODE_ARTIFACT_CHANGED'}
 }
 if((Read-Hash $signer) -cne $SignToolSha512.ToLowerInvariant()){throw 'CI_AUTHENTICODE_SIGNTOOL_CHANGED'}
 if((Read-Hash $node) -cne $NodeSha512.ToLowerInvariant()){throw 'CI_AUTHENTICODE_NODE_CHANGED'}
 $result.signatureVerification='PASS';$result.outcome='PREPARED';$result.signToolSha512=$SignToolSha512.ToLowerInvariant();$result.nodeSha512=$NodeSha512.ToLowerInvariant();$result.certificateSha256=$CertificateSha256.ToLowerInvariant()
 $result.requiredNext=@('TEST_EXACT_SIGNED_BYTES_ON_WINDOWS','DETACHED_APPROVAL_OF_SIGNED_BYTES','NEW_MANIFEST_FOR_SIGNED_BYTES','SERVER_VALIDATED_SIGNING_LINEAGE','IMMUTABLE_SIGNED_LAUNCHER_ISSUANCE')
 Write-CiJson (Join-Path $signed 'authenticode-preparation.json') $result
 $null=Assert-LocalPath ([IO.Path]::GetDirectoryName($destination)) $true
 # Move never overwrites an existing destination. Only the prepared cohort and
 # receipt leave the private tree; raw tool logs and input copies are removed.
 [IO.Directory]::Move($signed,$destination);$published=$true;$exit=0
}catch{
 $result.outcome='FAIL';$result.error=if($_.Exception.Message -cmatch '^CI_AUTHENTICODE_[A-Z_]+$'){$_.Exception.Message}else{'CI_AUTHENTICODE_PREPARATION_FAILED'}
}finally{
 if($nodeLock){$nodeLock.Dispose()};if($signerLock){$signerLock.Dispose()}
 if($privateCreated){
  try{
   $null=Assert-LocalPath $private $true
   if((Get-Item -LiteralPath $private -Force).CreationTimeUtc.Ticks -ne $privateCreatedAt){throw 'CI_AUTHENTICODE_PRIVATE_REPLACED'}
   Remove-Item -LiteralPath $private -Recurse -Force;$result.cleanup='PASS'
  }catch{$result.cleanup='FAIL';$result.outcome='FAIL';$result.error='CI_AUTHENTICODE_PRIVATE_CLEANUP_FAILED';$exit=1}
 }
}
$result.preparedFilesCreated=$published
Write-Output ($result|ConvertTo-Json -Depth 12 -Compress)
exit $exit
