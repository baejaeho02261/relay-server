param(
 [Parameter(Mandatory)][ValidateSet('dependencies','build','normalize','approve','native-probes','sdk-probe','abi-compare','report','sign')][string]$Kind,
 [Parameter(Mandatory)][string]$WorkRoot,[Parameter(Mandatory)][string]$Output,
 [string]$KeyFile,[string]$PolicyFile,[string]$Version,[int]$SecurityVersion=1,[string]$RunId
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
try {
 Write-Output "CI_STAGE_BEGIN $Kind"
 $native=Join-Path $WorkRoot 'GameConnect_Win64';$web=Join-Path $WorkRoot 'GameWeb';Set-Location -LiteralPath $native
 $node=(Get-Command node.exe -CommandType Application -ErrorAction Stop).Source
 function Run-Checked([string]$File,[string[]]$Arguments) { & $File @Arguments; if ($LASTEXITCODE -ne 0) { throw 'CI_CHILD_NONZERO_EXIT' } }
 if ($Kind -in @('build','native-probes')) {
  if (-not $env:BDS -or $env:BDS -match '[%&|<>^!"\r\n]') { throw 'CI_BDS_INVALID' }
  $rsvars=Join-Path $env:BDS 'bin\rsvars.bat'
  if (-not (Test-Path -LiteralPath $rsvars -PathType Leaf)) { throw 'CI_RAD_STUDIO_REQUIRED' }
  $lines=& $env:ComSpec /d /c ('call "'+$rsvars+'" >nul && set')
  if($LASTEXITCODE -ne 0){throw 'CI_RAD_ENV_FAILED'}
  foreach($line in $lines){$at=$line.IndexOf('=');if($at -gt 0){[Environment]::SetEnvironmentVariable($line.Substring(0,$at),$line.Substring($at+1))}}
 }
 switch ($Kind) {
  'dependencies' {
   Set-Location -LiteralPath $web
   Run-Checked (Get-Command npm.cmd).Source @('ci','--ignore-scripts','--no-audit','--no-fund')
   Run-Checked (Get-Command npm.cmd).Source @('rebuild','better-sqlite3','--build-from-source')
  }
  'build' {
   foreach($name in @('dcc64.exe','bcc64.exe','brcc32.exe')){if(-not(Test-Path -LiteralPath (Join-Path $env:BDS ('bin\'+$name)))){throw 'CI_RAD_CLASSIC_TOOLS_REQUIRED'}}
   if(-not(Test-Path -LiteralPath (Join-Path $env:BDS 'include\windows\sdk\d3d11.h'))){throw 'CI_RAD_SDK_HEADERS_REQUIRED'}
   $msbuild=(Get-Command msbuild.exe -CommandType Application -ErrorAction Stop).Source
   foreach($project in @('GameLauncher','GameConnect','GameOverlay')){Run-Checked $msbuild @(($project+'.dproj'),'/t:Rebuild','/p:Config=Release','/p:Platform=Win64','/m:1','/nr:false','/nologo','/v:minimal')}
   $paths=@{A='launcher';B='client';O='overlay'}
   foreach($role in @('A','B','O')){
    $files=@(Get-ChildItem -LiteralPath (Join-Path $native ('Win64\Release\'+$paths[$role])) -Filter '*.exe' -File)
    if($files.Count -ne 1 -or $files[0].Length -le 0){throw 'CI_BUILD_OUTPUT_COUNT'}
    Copy-Item -LiteralPath $files[0].FullName -Destination (Join-Path $Output ($role+'.exe')) -ErrorAction Stop
   }
   $header=Get-Content -LiteralPath (Join-Path $native 'imgui\vendor\imgui.h') -Raw
   if($header -notmatch '#define\s+IMGUI_VERSION\s+"([^"]+)"'){throw 'CI_IMGUI_VERSION_MISSING'}
   $imgui=$Matches[1];$dcc=(Get-Item -LiteralPath (Join-Path $env:BDS 'bin\dcc64.exe')).VersionInfo.FileVersion;$bcc=(Get-Item -LiteralPath (Join-Path $env:BDS 'bin\bcc64.exe')).VersionInfo.FileVersion
   if(-not $env:WindowsSDKVersion){throw 'CI_WINDOWS_SDK_VERSION_REQUIRED'}
   @{delphi="dcc64 $dcc";cpp="classic bcc64 ELF $bcc";windowsSdk=$env:WindowsSDKVersion.TrimEnd('\');imgui=$imgui}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Output 'toolchain.json') -Encoding utf8NoBOM
  }
  'normalize' { Run-Checked (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $native 'imgui\bridge\Normalize-PE-Unwind.ps1'),'-ImagePath',(Join-Path $Output 'O.exe')) }
  'approve' { $arguments=@((Join-Path $PSScriptRoot 'ci-artifacts.js'),'prepare',$Output,$KeyFile,$Version,[string]$SecurityVersion,(Join-Path $Output 'toolchain.json'),(Join-Path $web 'maintenance\source-manifest.json'));if($PolicyFile){$arguments+=$PolicyFile};Run-Checked $node $arguments }
  'native-probes' { Run-Checked $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'tests\Build_NativeProbes_Win64.bat')+'"')) }
  'sdk-probe' { Run-Checked $env:ComSpec @('/d','/c',('call "'+(Join-Path $native 'tests\Build_NativeAbi_SDK_Win64.bat')+'"')) }
  'abi-compare' { Run-Checked (Join-Path $PSHOME 'pwsh.exe') @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $native 'tests\Compare-NativeAbi.ps1'),'-DelphiProbe',(Join-Path $native 'tests\native_probe_build\NativeAbiProbe.exe'),'-SdkProbe',(Join-Path $native 'tests\native_sdk_build\NativeAbiSdkProbe.exe')) }
  'report' { Run-Checked $node @((Join-Path $PSScriptRoot 'ci-artifacts.js'),'report',$Output,(Join-Path $Output 'runner-results.json')) }
  'sign' { Run-Checked $node @((Join-Path $PSScriptRoot 'ci-artifacts.js'),'sign',$Output,$KeyFile,$RunId) }
 }
 Write-Output "CI_STAGE_PASS $Kind";exit 0
} catch { Write-Error ('CI_STAGE_FAILED '+$Kind+' (review bounded stage log)');exit 1 }
