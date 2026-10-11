param(
 [Parameter(Mandatory)][ValidateSet('environment','create-key','export-key','run','check-output')][string]$Action,
 [string]$BdsRoot=$env:BDS,[string]$CiKeyFile,[string]$ReleaseKeyFile,[string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$toolRoot=$PSScriptRoot
$sourceRoot=[IO.Path]::GetFullPath((Join-Path $toolRoot '..\..'))
$helper=Join-Path $toolRoot 'ci-workflow.js'
$exitCode=1;$transcript=$false
$log=Join-Path $toolRoot ('ci-workflow-'+$Action+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)+'.log')
function Input-Path([string]$Value,[string]$Prompt){
 if(-not $Value){$Value=Read-Host $Prompt}
 $Value=$Value.Trim();if($Value.StartsWith('"') -and $Value.EndsWith('"')){$Value=$Value.Substring(1,$Value.Length-2)}
 if(-not $Value -or -not [IO.Path]::IsPathFullyQualified($Value)){throw 'Enter an absolute path. Explorer Copy as path is accepted.'}
 return [IO.Path]::GetFullPath($Value)
}
function Invoke-Helper([string[]]$Arguments){
 $result=& $script:node $helper @Arguments
 if($LASTEXITCODE -ne 0){throw 'CI helper failed. Resolve the error printed immediately above; no approval or PASS was created.'}
 $text=$result -join [Environment]::NewLine
 Write-Host $text
 return ($text|ConvertFrom-Json)
}
function Require-File([string]$File,[string]$Instruction){if(-not(Test-Path -LiteralPath $File -PathType Leaf)){throw ($Instruction+' Missing: '+$File)}}
function Assert-Environment {
 foreach($name in @('npm.cmd','openssl.exe','cl.exe')){
  if(-not(Get-Command $name -CommandType Application -ErrorAction SilentlyContinue)){throw ($name+' is required. Use a Visual Studio x64 Native Tools command prompt with Node.js and OpenSSL on PATH, then call this BAT.')}
 }
 # npm rebuild uses node-gyp: honor explicit Python configuration before PATH discovery.
 $pythonConfigured=$false
 foreach($name in @('NODE_GYP_FORCE_PYTHON','npm_config_python','PYTHON')){
  $candidate=[Environment]::GetEnvironmentVariable($name)
  if($candidate){if((Test-Path -LiteralPath $candidate -PathType Leaf) -or (Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue)){$pythonConfigured=$true;break}else{throw ('Configured Python executable is missing: '+$name)}}
 }
 if(-not $pythonConfigured){foreach($name in @('python.exe','python3.exe','py.exe')){if(Get-Command $name -CommandType Application -ErrorAction SilentlyContinue){$pythonConfigured=$true;break}}}
 if(-not $pythonConfigured){throw 'Python is required by npm rebuild better-sqlite3 (node-gyp). Install Python or set npm_config_python to its full executable path.'}
 if($env:VSCMD_ARG_TGT_ARCH -and $env:VSCMD_ARG_TGT_ARCH -ne 'x64'){throw 'Open the x64 Native Tools Command Prompt for Visual Studio; the active MSVC target is not x64.'}
 if(-not $script:BdsRoot){$script:BdsRoot=Read-Host 'RAD Studio root folder containing bin\dcc64.exe (BDS)'}
 $script:BdsRoot=Input-Path $script:BdsRoot 'RAD Studio root folder'
 foreach($name in @('bin\dcc64.exe','bin\bcc64.exe','bin\brcc32.exe','bin\rsvars.bat','include\windows\sdk\d3d11.h')){Require-File (Join-Path $script:BdsRoot $name) 'Install the RAD Studio classic Win64 Delphi/C++ compiler and Windows SDK headers.'}
 $env:BDS=$script:BdsRoot
 foreach($name in @('spec.json','deployment-policy.json','reviewed-build-inputs.json')){
  $instructions=switch($name){'spec.json'{'Run Create_Spec.bat and enter the actual release/security versions.'};'deployment-policy.json'{'Export the CURRENT policy from the administrator Security / Deployment page and place it beside this BAT. Do not use an empty policy.'};'reviewed-build-inputs.json'{'Run Observe_Build_Inputs.bat, independently review the observed inputs, then run Approve_Build_Inputs.bat with the reviewed digest.'}}
  Require-File (Join-Path $toolRoot $name) $instructions
 }
 Write-Host 'Checking source hashes and release prerequisites...'
 return (Invoke-Helper @('preflight',$sourceRoot,$toolRoot))
}
try {
 if(-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7){throw '64-bit PowerShell 7 is required; Windows PowerShell 5.1 cannot run this CI workflow.'}
 Start-Transcript -LiteralPath $log -NoClobber|Out-Null;$transcript=$true
 Write-Host ('Log: '+$log)
 $nodeCommand=Get-Command node.exe -CommandType Application -ErrorAction SilentlyContinue
 if(-not $nodeCommand){throw 'Install supported 64-bit Node.js and reopen the command prompt (see GameWeb/package.json engines).'}
 $script:node=$nodeCommand.Source
 foreach($name in @('services\boundedArtifactRead.js','services\desktopReleaseProvenance.js','services\strictJson.js','tools\release-provenance.js','tools\ci-workflow.js')){Require-File (Join-Path $sourceRoot ('GameWeb\'+$name)) 'Source package is incomplete. Restore the COMPLETE matching GameWeb package; do not mix versions.'}
 switch($Action){
  'environment' {$null=Assert-Environment;Write-Host 'Prerequisite file checks passed. Windows builds/tests have NOT run. CI separately verifies reviewed compiler input hashes before and after building.'}
  'create-key' {
   if(-not $CiKeyFile){$suggested=Join-Path $env:LOCALAPPDATA ('GameConnectKeys\ci-'+[Guid]::NewGuid().ToString('N')+'\ci-private.pem');$answer=Read-Host ('New CI private key path outside the source folder [Enter: '+$suggested+']');$CiKeyFile=if($answer){$answer}else{$suggested}}
   $CiKeyFile=Input-Path $CiKeyFile 'New CI private key absolute path'
   $base=$sourceRoot.TrimEnd('\')+'\';if($CiKeyFile.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)){throw 'CI private keys must remain outside the source and CI output directories.'}
   $parent=Split-Path -Parent $CiKeyFile
   if(Test-Path -LiteralPath $parent){throw 'For safe key permissions, choose a NEW parent directory. Existing directories or keys are not overwritten.'}
   $cursor=Split-Path -Parent $parent
   while($cursor){if(Test-Path -LiteralPath $cursor){if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Key directory cannot be under a junction or symbolic link.'}};$next=Split-Path -Parent $cursor;if($next -eq $cursor){break};$cursor=$next}
   . (Join-Path $sourceRoot 'GameWeb\ci\CiCommon.ps1')
   New-CiPrivateDirectory $parent
   $null=Invoke-Helper @('create-key',$sourceRoot,$CiKeyFile)
   Write-Host ('Private key saved with restricted Windows ACL: '+$CiKeyFile)
   Write-Host 'Keep this key private. Next: Export_CI_Public_Key.bat. Only its public JSON is registered in the web administrator.'
  }
  'export-key' {
   $CiKeyFile=Input-Path $CiKeyFile 'CI private key absolute path (not the EXE approval key)'
   $target=Join-Path $toolRoot 'ci-public-key.json'
   if(Test-Path -LiteralPath $target){throw 'ci-public-key.json already exists. Keep its registered key; for intentional rotation, archive that PUBLIC file before exporting a new key. No key was overwritten.'}
   $null=Invoke-Helper @('export-key',$sourceRoot,$CiKeyFile,$target)
   Write-Host ('Register this PUBLIC JSON in Security / Deployment > CI signer: '+$target)
   Write-Host 'The server must trust this dedicated CI signer before CI evidence can be accepted. Never upload a private PEM.'
  }
  'run' {
   $spec=Assert-Environment
   $CiKeyFile=Input-Path $CiKeyFile 'CI private key absolute path'
   $ReleaseKeyFile=Input-Path $ReleaseKeyFile 'EXISTING EXE approval private key absolute path (trusted by exported policy)'
   Require-File (Join-Path $toolRoot 'ci-public-key.json') 'Run Export_CI_Public_Key.bat for the selected CI key first.'
   $null=Invoke-Helper @('key-check',$sourceRoot,$toolRoot,$CiKeyFile,$ReleaseKeyFile)
   if($OutputDirectory){throw 'Run_Windows_CI always writes a NEW run folder under tools\ci-runs. OutputDirectory is only for Check_CI_Output.'}
   $runId='windows-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
   $runs=Join-Path $toolRoot 'ci-runs';if(-not(Test-Path -LiteralPath $runs)){[IO.Directory]::CreateDirectory($runs)|Out-Null}
   $OutputDirectory=Join-Path $runs $runId
   Write-Host ('Starting REAL Windows build/tests. Run output: '+$OutputDirectory)
   Write-Host 'This runner creates NEW final A/B/O. Previously uploaded/manual-build EXEs are not the tested files.'
   $runner=Join-Path $sourceRoot 'GameWeb\ci\Invoke-WindowsCI.ps1'
   $runnerArgs=@('-NoLogo','-NoProfile','-File',$runner,'-SourceRoot',$sourceRoot,'-OutputDirectory',$OutputDirectory,'-Version',[string]$spec.version,'-SecurityVersion',[string]$spec.securityVersion,'-RunId',$runId,'-BuildInputLockFile',(Join-Path $toolRoot 'reviewed-build-inputs.json'),'-BdsRoot',$script:BdsRoot,'-ReleaseKeyFile',$ReleaseKeyFile,'-CiKeyFile',$CiKeyFile,'-PolicyFile',(Join-Path $toolRoot 'deployment-policy.json'))
   & (Join-Path $PSHOME 'pwsh.exe') @runnerArgs
   $runnerExit=$LASTEXITCODE
   if($runnerExit -ne 0){Write-Host ('FAILED run details: '+(Join-Path $OutputDirectory 'runner-results.json'));Write-Host ('Stage logs: '+(Join-Path $OutputDirectory 'logs'));throw ('Windows CI did not pass (exit '+$runnerExit+'). No publication approval is claimed. Fix the FIRST failed stage before rerunning.')}
   $null=Invoke-Helper @('check-output',$OutputDirectory,(Join-Path $toolRoot 'ci-public-key.json'))
   Write-Host ('Verified final files, manifest and signed evidence: '+$OutputDirectory)
   Write-Host 'Web order: register CI public signer; plan this run manifest.json; register THIS run A/B/O and their approval JSONs with the same manifest ID; complete manifest registration; register ci-evidence.json; inspect eligibility and publish.'
   Write-Host 'Do not rebuild, rename/reprocess with approval tools, regenerate a manifest or mix files from different runs. Server trust/policy is checked by the web server.'
  }
  'check-output' {
   $OutputDirectory=Input-Path $OutputDirectory 'Completed CI run folder absolute path (tools\ci-runs\windows-...)'
   Require-File (Join-Path $toolRoot 'ci-public-key.json') 'Export the expected CI signer public JSON beside this BAT first.'
   $null=Invoke-Helper @('check-output',$OutputDirectory,(Join-Path $toolRoot 'ci-public-key.json'))
   Write-Host 'Local signature, final-file bindings, logs and three PASS outcomes verified. Server signer trust and publication eligibility are NOT asserted here.'
  }
 }
 $exitCode=0
} catch {
 Write-Host ('ERROR: '+$_.Exception.Message) -ForegroundColor Red
 Write-Host ('Log: '+$log)
} finally {if($transcript){Stop-Transcript|Out-Null}}
exit $exitCode
