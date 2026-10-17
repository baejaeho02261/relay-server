param([string]$InputFile='', [string]$ResultFile='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$selectedRoot=$null;$node=$null;$exitCode=1
try {
 if(-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7){throw 'LIFECYCLE_WINDOWS_POWERSHELL7_X64_REQUIRED'}
 . (Join-Path $PSScriptRoot '..\ci\CiCommon.ps1')
 $node=[string](Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
 $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
 $id='security-authority-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8)
 if($InputFile){
  $InputFile=[IO.Path]::GetFullPath($InputFile);$file=Get-Item -LiteralPath $InputFile
  if($file.Length -gt 1048576){throw 'LIFECYCLE_INPUT_TOO_LARGE'}
  $config=[IO.File]::ReadAllText($InputFile)|ConvertFrom-Json -AsHashtable -Depth 12
  if($config.version -ne 1 -or @($config.Keys|Where-Object{$_ -notin @('version','releaseVersion','artifacts','faultArtifacts','scenarios','nativeReceiveProbe','verificationContext','policyFile')}).Count -gt 0){throw 'LIFECYCLE_INPUT_INVALID'}
 } else {
  Write-Host 'Build normal Release A/B/O and the three tests\product-faults IDE projects first.'
  Write-Host 'This runs existing files on a NEW isolated localhost server. No CI, command-line Delphi compiler, production key or server reset is required.'
  $version=(Read-Host 'Actual numeric A/B/O release version [Enter: 1.0.0]').Trim();if(-not $version){$version='1.0.0'}
  $config=@{version=1;releaseVersion=$version;artifacts=@{};faultArtifacts=@{}}
  $names=@{A='GameLauncher';B='GameConnect';O='GameOverlay'}
  foreach($group in @('artifacts','faultArtifacts')){
   foreach($role in @('A','B','O')){
    $relative=if($group -eq 'artifacts'){'GameConnect_Win64\bin\'+$names[$role]+'.exe'}else{'GameConnect_Win64\tests\product-faults\bin\'+$names[$role]+'FaultTest.exe'}
    $default=Join-Path $root $relative
    $answer=(Read-Host ($group+' '+$role+' absolute EXE path [Enter: '+$default+']')).Trim().Trim('"')
    if(-not $answer){$answer=$default};$config[$group][$role]=[IO.Path]::GetFullPath($answer)
   }
  }
  $policy=(Read-Host 'Reviewed exported authority policy JSON [Enter: explicit default enforce test policy]').Trim().Trim('"')
  if($policy){$config.policyFile=[IO.Path]::GetFullPath($policy)}
  $context=(Read-Host 'Optional admin-exported verification-context JSON [Enter: local results only]').Trim().Trim('"')
  if($context){$config.verificationContext=[IO.Path]::GetFullPath($context)}
 }
 if(-not $config.ContainsKey('artifacts') -or -not $config.ContainsKey('faultArtifacts')){throw 'LIFECYCLE_FINAL_AND_DEDICATED_A_B_O_REQUIRED'}
 $config.scenarios=@('lifecycle-cleanup-success','authority-measurement-skipped','authority-report-stopped','authority-local-stop-held')
 $null=$config.Remove('nativeReceiveProbe')
 $selectedRoot=Join-Path ([IO.Path]::GetTempPath()) ('GameLifecycleInputs-'+[Guid]::NewGuid().ToString('N'))
 New-CiPrivateDirectory $selectedRoot
 $selected=Join-Path $selectedRoot 'selected-inputs.json'
 [IO.File]::WriteAllText($selected,($config|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
 $report=if($ResultFile){[IO.Path]::GetFullPath($ResultFile)}else{Join-Path $PSScriptRoot ($id+'-results.json')}
 Write-Host 'Selected paths are held in private temporary storage for this run only.'
 Write-Host 'Faults start only AFTER a genuine server grant. Server expiry uses unchanged real time. Dedicated faults are NOT final Release execution.'
 & (Join-Path $PSScriptRoot 'product-fault-tests.ps1') -InputFile $selected -ResultFile $report -GeneratedInputRoot $selectedRoot
 $exitCode=$LASTEXITCODE
 if($exitCode -eq 0){
  $observed=Read-CiJson $report
  if($observed.outcome -ne 'PASS'){$exitCode=1}
 }
} catch {
 $code=if($_.Exception.Message -cmatch '^[A-Z][A-Z0-9_]+$'){$_.Exception.Message}else{'LIFECYCLE_WINDOWS_RUNNER_FAILED'}
 Write-Host ('ERROR: '+$code);$exitCode=1
} finally {
 if($selectedRoot -and $node -and (Test-Path -LiteralPath $selectedRoot)){
  & $node (Join-Path $PSScriptRoot 'test-evidence-cleanup.js') cleanup $selectedRoot
  if($LASTEXITCODE -ne 0){Write-Host 'ERROR: LIFECYCLE_SELECTED_INPUT_CLEANUP_FAILED';$exitCode=1}
 }
}
exit $exitCode
