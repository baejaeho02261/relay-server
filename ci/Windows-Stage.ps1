param(
 [Parameter(Mandatory)][ValidateSet('dependencies','build-inputs','build-inputs-after','build','normalize','approve','native-probes','native-hash-compare','overlay-contracts','compatibility-probes','device-identity','sdk-probe','abi-compare','report','sign')][string]$Kind,
 [Parameter(Mandatory)][string]$WorkRoot,[Parameter(Mandatory)][string]$Output,
 [string]$BuildInputLockFile,[string]$KeyFile,[string]$PolicyFile,[string]$Version,[int]$SecurityVersion=1,[string]$RunId
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
try {
 Write-Output "CI_STAGE_BEGIN $Kind"
 $native=Join-Path $WorkRoot 'GameConnect_Win64';$web=Join-Path $WorkRoot 'GameWeb';Set-Location -LiteralPath $native
 $node=(Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
 function Run-Checked([string]$File,[string[]]$Arguments) {
  & $File @Arguments
  if ($LASTEXITCODE -ne 0) {
   $failure=[InvalidOperationException]::new('CI_CHILD_NONZERO_EXIT')
   $failure.Data['childExitCode']=[int]$LASTEXITCODE
   throw $failure
  }
 }
 if ($Kind -in @('build','native-probes','overlay-contracts','device-identity')) {
  if (-not $env:BDS -or $env:BDS -match '[%&|<>^!"\r\n]') { throw 'CI_BDS_INVALID' }
  $rsvars=Join-Path $env:BDS 'bin\rsvars.bat'
  if (-not (Test-Path -LiteralPath $rsvars -PathType Leaf)) { throw 'CI_RAD_STUDIO_REQUIRED' }
  $lines=& $env:ComSpec /d /c ('call "'+$rsvars+'" >nul && set')
  if($LASTEXITCODE -ne 0){throw 'CI_RAD_ENV_FAILED'}
  foreach($line in $lines){$at=$line.IndexOf('=');if($at -gt 0){[Environment]::SetEnvironmentVariable($line.Substring(0,$at),$line.Substring($at+1))}}
 }
 if ($env:GAME_IMGUI_BCC64 -and $Kind -in @('build','overlay-contracts')) {
  $approvedCompiler=[IO.Path]::GetFullPath((Join-Path $env:BDS 'bin\bcc64.exe'))
  if(-not [string]::Equals([IO.Path]::GetFullPath($env:GAME_IMGUI_BCC64),$approvedCompiler,[StringComparison]::OrdinalIgnoreCase)){throw 'CI_UNAPPROVED_COMPILER_OVERRIDE'}
 }
 switch ($Kind) {
  'dependencies' {
   Set-Location -LiteralPath $web
   $npm=(Get-Command npm.cmd -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
   Run-Checked $npm @('ci','--engine-strict','--ignore-scripts','--no-audit','--no-fund')
   Run-Checked $npm @('rebuild','better-sqlite3','--build-from-source')
  }
  {$_ -in @('build-inputs','build-inputs-after')} {
   Run-Checked $node @((Join-Path $PSScriptRoot 'build-input-lock.js'),'verify',$native,$web,$env:BDS,$BuildInputLockFile,(Join-Path $Output ($Kind+'.json')))
  }
  'build' {
   foreach($name in @('dcc64.exe','bcc64.exe','brcc32.exe')){if(-not(Test-Path -LiteralPath (Join-Path $env:BDS ('bin\'+$name)))){throw 'CI_RAD_CLASSIC_TOOLS_REQUIRED'}}
   if(-not(Test-Path -LiteralPath (Join-Path $env:BDS 'include\windows\sdk\d3d11.h'))){throw 'CI_RAD_SDK_HEADERS_REQUIRED'}
   # rsvars can expose Framework and Visual Studio MSBuild at the same time.
   # Preserve its PATH precedence and pass exactly one executable to children.
   $msbuild=(Get-Command msbuild.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
   Write-Output ('CI_MSBUILD_PATH '+$msbuild)
   # A snapshot contains immutable resource inputs, never local compiled RES
   # caches. Rebuild all three with the reviewed compiler before Delphi runs.
   $projects=@('GameLauncher','GameConnect','GameOverlay')
   foreach($project in $projects){
    if(Test-Path -LiteralPath (Join-Path $native ($project+'Resources.res'))){throw 'CI_GENERATED_RESOURCE_IN_SNAPSHOT'}
   }
   Run-Checked (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $native 'tests\Test-BuildIsolation.ps1'),'-NativeRoot',$native,'-MsBuildPath',$msbuild)
   foreach($project in $projects){
    Run-Checked (Join-Path $env:BDS 'bin\brcc32.exe') @(('-fo'+$project+'Resources.res'),($project+'.rc'))
    $resource=Get-Item -LiteralPath (Join-Path $native ($project+'Resources.res')) -ErrorAction Stop
    if($resource.PSIsContainer -or $resource.Length -le 32){throw 'CI_RESOURCE_BUILD_INVALID'}
    Run-Checked $msbuild @(($project+'.dproj'),'/t:Rebuild','/p:Config=Release','/p:Platform=Win64','/m:1','/nr:false','/nologo','/v:minimal')
   }
   Run-Checked $node @((Join-Path $web 'scripts\check-connect-project.js'))
   # Only this fresh snapshot's outputs may enter the tested bundle. Product
   # DCUs and compiler staging remain isolated; final EXEs share one folder.
   $finalDirectory=Join-Path $native 'bin'
   $finalFiles=@(Get-ChildItem -LiteralPath $finalDirectory -Filter '*.exe' -File)
   if($finalFiles.Count -ne 3){throw 'CI_BUILD_OUTPUT_COUNT'}
   foreach($role in @('A','B','O')){
    $files=@($finalFiles|Where-Object{$_.Name -cmatch ('^'+$role+'_Release_[a-f0-9]{32}\.exe$')})
    if($files.Count -ne 1 -or $files[0].Length -le 0 -or ($files[0].Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'CI_BUILD_OUTPUT_COUNT'}
    Copy-Item -LiteralPath $files[0].FullName -Destination (Join-Path $Output ($role+'.exe')) -ErrorAction Stop
   }
   $header=Get-Content -LiteralPath (Join-Path $native 'imgui\vendor\imgui.h') -Raw
   if($header -notmatch '#define\s+IMGUI_VERSION\s+"([^"]+)"'){throw 'CI_IMGUI_VERSION_MISSING'}
   $imgui=$Matches[1];$dcc=(Get-Item -LiteralPath (Join-Path $env:BDS 'bin\dcc64.exe')).VersionInfo.FileVersion;$bcc=(Get-Item -LiteralPath (Join-Path $env:BDS 'bin\bcc64.exe')).VersionInfo.FileVersion
   $lockObservation=Get-Content -LiteralPath (Join-Path $Output 'build-inputs.json') -Raw|ConvertFrom-Json
   if($lockObservation.status -ne 'PASS'){throw 'CI_REVIEWED_BUILD_INPUT_LOCK_REQUIRED'}
   $classicSdk='BDS classic headers SHA512 '+$lockObservation.sdkHeaderSha512
   @{delphi="dcc64 $dcc";cpp="classic bcc64 ELF $bcc";windowsSdk=$classicSdk;imgui=$imgui}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Output 'toolchain.json') -Encoding utf8NoBOM
   $observed=[ordered]@{version=1;node=(& $node --version);nodeSha512=(Get-FileHash -LiteralPath $node -Algorithm SHA512).Hash.ToLowerInvariant();windowsBuild=[Environment]::OSVersion.Version.ToString();windowsSdk=$classicSdk;buildInputSha512=$lockObservation.inputSha512;imgui=$imgui;files=[ordered]@{}}
   foreach($name in @('dcc64.exe','bcc64.exe','brcc32.exe')){$observed.files[$name]=(Get-FileHash -LiteralPath (Join-Path $env:BDS ('bin\'+$name)) -Algorithm SHA512).Hash.ToLowerInvariant()}
   foreach($name in @('package.json','package-lock.json')){$observed.files[$name]=(Get-FileHash -LiteralPath (Join-Path $web $name) -Algorithm SHA512).Hash.ToLowerInvariant()}
   foreach($name in @('imgui\vendor\imgui.h','imgui\bridge\game_imgui_bridge.cpp','imgui\bridge\game_imgui_dx11.cpp')){$observed.files[$name]=(Get-FileHash -LiteralPath (Join-Path $native $name) -Algorithm SHA512).Hash.ToLowerInvariant()}
   $observed|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $Output 'observed-build-inputs.json') -Encoding utf8NoBOM
   Write-Output ('ACTUAL_BUILD_INPUTS '+($observed|ConvertTo-Json -Depth 8 -Compress))

  }
  'normalize' {
   Run-Checked (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $native 'imgui\bridge\Normalize-PE-Unwind.ps1'),'-ImagePath',(Join-Path $Output 'O.exe'))
   Run-Checked $node @((Join-Path $web 'tools\audit-final-artifacts.js'),(Join-Path $Output 'A.exe'),(Join-Path $Output 'B.exe'),(Join-Path $Output 'O.exe'),(Join-Path $Output 'final-artifact-audit.json'))
   Run-Checked $node @((Join-Path $PSScriptRoot 'cfg-evidence.js'),$Output,(Join-Path $Output 'build-inputs.json'),(Join-Path $Output 'cfg-evidence.json'))
  }
  'approve' { $arguments=@((Join-Path $PSScriptRoot 'ci-artifacts.js'),'prepare',$Output,$KeyFile,$Version,[string]$SecurityVersion,(Join-Path $Output 'toolchain.json'),(Join-Path $web 'maintenance\source-manifest.json'));if($PolicyFile){$arguments+=$PolicyFile};Run-Checked $node $arguments }
  'native-probes' { Run-Checked $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'tests\Build_NativeProbes_Win64.bat')+'"')) }
  'native-hash-compare' { Run-Checked $node @((Join-Path $web 'scripts\compare-native-hashes.js'),'--hash-probe',(Join-Path $native 'tests\native_probe_build\IntegrityHashProbe.exe'),'--crc-probe',(Join-Path $native 'tests\native_probe_build\CrcProbe.exe'),'--mode-probe',(Join-Path $native 'tests\native_probe_build\HashProbe.exe'),'--pe-probe',(Join-Path $native 'tests\native_probe_build\PeCorpusProbe.exe'),'--crc-pe-probe',(Join-Path $native 'tests\native_probe_build\CrcPeProbe.exe')) }
  'overlay-contracts' { Run-Checked $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'tests\Build_OverlayContracts_Win64.bat')+'"')) }
  'compatibility-probes' { Run-Checked $node @((Join-Path $PSScriptRoot 'collect-compatibility.js'),$native,(Join-Path $Output 'compatibility-observations.json')) }
  'device-identity' { Run-Checked $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'tests\Build_DeviceIdentityProbe_Win64.bat')+'"')) }
  'sdk-probe' { Run-Checked (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $PSScriptRoot 'Observe-SdkProbeInputs.ps1'),'-OutputFile',(Join-Path $Output 'sdk-probe-inputs.json')); Run-Checked $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'tests\Build_NativeAbi_SDK_Win64.bat')+'"')) }
  'abi-compare' { Run-Checked (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $native 'tests\Compare-NativeAbi.ps1'),'-DelphiProbe',(Join-Path $native 'tests\native_probe_build\NativeAbiProbe.exe'),'-SdkProbe',(Join-Path $native 'tests\native_sdk_build\NativeAbiSdkProbe.exe')) }
  'report' { Run-Checked $node @((Join-Path $PSScriptRoot 'ci-artifacts.js'),'report',$Output,(Join-Path $Output 'runner-results.json')) }
  'sign' { Run-Checked $node @((Join-Path $PSScriptRoot 'ci-artifacts.js'),'sign',$Output,$KeyFile,$RunId) }
 }
 Write-Output "CI_STAGE_PASS $Kind";exit 0
} catch {
 # Keep the original static failure code and child exit status. Arbitrary
 # exception messages, arguments and environment values can contain secrets.
 $detail=@{stage=$Kind;error='CI_STAGE_EXCEPTION';exceptionType=$_.Exception.GetType().FullName;nativeErrorCode=$null;childExitCode=$null}
 $cause=$_.Exception
 for($depth=0;$null -ne $cause -and $depth -lt 8;$depth++){
  $detail.exceptionType=$cause.GetType().FullName
  if($cause.Message -match '^CI_[A-Z0-9_]+$'){$detail.error=$cause.Message}
  if($cause -is [ComponentModel.Win32Exception]){$detail.nativeErrorCode=[int]$cause.NativeErrorCode}
  if($cause.Data.Contains('childExitCode')){$detail.childExitCode=[int]$cause.Data['childExitCode']}
  $cause=$cause.InnerException
 }
 Write-Output ('CI_STAGE_DETAIL '+($detail|ConvertTo-Json -Compress))
 Write-Output ('CI_STAGE_FAILED '+$Kind)
 exit 1
}
