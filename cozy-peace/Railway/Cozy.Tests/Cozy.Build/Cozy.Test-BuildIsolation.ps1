param([Parameter(Mandatory)][string]$NativeRoot,[Parameter(Mandatory)][string]$MsBuildPath)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=(Resolve-Path -LiteralPath $NativeRoot).ProviderPath
$project=Join-Path $root 'Cozy.Projects\Cozy.Client\Cozy.Client.dproj';$base=@($project,'/t:ValidateProductionIsolation','/p:Config=Release','/p:Platform=Win64','/m:1','/nr:false','/nologo','/v:minimal')
function Check([string]$Name,[string[]]$Extra,[bool]$Allow) {
 $text=& $MsBuildPath @base @Extra 2>&1
 $code=$LASTEXITCODE
 Write-Output ($text|Out-String)
 if($Allow){if($code -ne 0 -or ($text|Out-String) -notmatch 'GAME_BUILD_ISOLATION_OK'){throw ('ISOLATION_VALID_BUILD_REJECTED_'+$Name)}}
 elseif($code -eq 0 -or ($text|Out-String) -notmatch 'GAME_BUILD_'){throw ('ISOLATION_NEGATIVE_NOT_REJECTED_'+$Name)}
 Write-Output ('PASS BUILD_ISOLATION '+$Name)
}
# This destructive-output contract runs only on a fresh test working copy.
# Never overwrite a developer's existing EXE or unit cache with test sentinels.
$roleNames=@('Cozy.Launcher','Cozy.Client','Cozy.Overlay')
foreach($name in $roleNames){
 $directory=Join-Path $root ('Cozy.Projects\'+$name)
 if(Test-Path -LiteralPath (Join-Path $directory ($name+'.exe'))){throw 'ISOLATION_FRESH_TEST_TREE_REQUIRED'}
 $cache=Join-Path $directory 'dcu'
 if(Test-Path -LiteralPath $cache){
  $item=Get-Item -LiteralPath $cache -Force
  if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @(Get-ChildItem -LiteralPath $cache -Force).Count -ne 0){throw 'ISOLATION_FRESH_TEST_TREE_REQUIRED'}
 }
}
$temporaryRoot=Join-Path ([IO.Path]::GetTempPath()) ('Cozy.BuildIsolation.'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot)|Out-Null
try {
# Every role owns one project-local dcu directory. Debug/Release deliberately
# share it, so both configurations must clean it before compiling fresh units.
foreach($config in @('Debug','Release')) {
 $base[2]='/p:Config='+$config
 foreach($role in @(@('Cozy.Launcher','A'),@('Cozy.Client','B'),@('Cozy.Overlay','O'))) {
  $projectDirectory=Join-Path $root ('Cozy.Projects\'+$role[0])
  $base[0]=Join-Path $projectDirectory ($role[0]+'.dproj')
  $label=$role[1]+'-'+$config
  Check ($label+'-clean-default') @() $true
  Check ($label+'-empty-IDE-output') @('/p:DCC_DcuOutput=','/p:DCC_ExeOutput=') $true
  $dcu=Join-Path $projectDirectory 'dcu';$exe=$projectDirectory
  Check ($label+'-absolute-output') @(('/p:DCC_DcuOutput='+$dcu),('/p:DCC_ExeOutput='+$exe)) $true
  Check ($label+'-relative-output') @('/p:DCC_DcuOutput=dcu','/p:DCC_ExeOutput=.') $true
  Check ($label+'-trailing-output-separator') @(('/p:DCC_DcuOutput='+$dcu+'\'),('/p:DCC_ExeOutput='+$exe+'\')) $true
  $otherProject=if($role[0] -eq 'Cozy.Client'){'Cozy.Launcher'}else{'Cozy.Client'}
  $otherDirectory=Join-Path $root ('Cozy.Projects\'+$otherProject)
  $otherDcu=Join-Path $otherDirectory 'dcu'
  foreach($directory in @($dcu,$otherDcu)){[IO.Directory]::CreateDirectory($directory)|Out-Null}
  $ownSentinel=Join-Path $dcu 'configuration-test.dcu'
  $ownExe=Join-Path $projectDirectory ($role[0]+'.exe')
  $preserved=@((Join-Path $otherDcu 'other-project-test.dcu'),(Join-Path $otherDirectory ($otherProject+'.exe')),(Join-Path $projectDirectory 'output-isolation-source-sentinel.txt'))
  $sentinels=@($ownSentinel,$ownExe)+$preserved
  foreach($file in $sentinels){if(Test-Path -LiteralPath $file){throw 'ISOLATION_SENTINEL_ALREADY_EXISTS'}}
  try {
   foreach($file in $sentinels){[IO.File]::WriteAllText($file,'owned output contract sentinel')}
   Check ($label+'-other-project-dcu') @(('/p:DCC_DcuOutput='+$otherDcu)) $false
   Check ($label+'-other-project-exe') @(('/p:DCC_ExeOutput='+$otherDirectory)) $false
   Check ($label+'-legacy-shared-dcu') @(('/p:DCC_DcuOutput='+(Join-Path $root ('build\'+$role[1]+'\Win64\'+$config+'\dcu')))) $false
   Check ($label+'-legacy-shared-exe') @(('/p:DCC_ExeOutput='+(Join-Path $root 'bin'))) $false
   foreach($file in $sentinels){if(-not(Test-Path -LiteralPath $file) -or [IO.File]::ReadAllText($file) -ne 'owned output contract sentinel'){throw 'ISOLATION_REJECTED_OUTPUT_WAS_CHANGED'}}
   Check ($label+'-fresh-project-output') @() $true
   if((Test-Path -LiteralPath $ownSentinel) -or (Test-Path -LiteralPath $ownExe)){throw 'ISOLATION_STALE_PROJECT_OUTPUT_REUSED'}
   foreach($file in $preserved){if(-not(Test-Path -LiteralPath $file) -or [IO.File]::ReadAllText($file) -ne 'owned output contract sentinel'){throw 'ISOLATION_OTHER_PROJECT_OR_SOURCE_DAMAGED'}}
  } finally {foreach($file in $sentinels){if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}}}
 }
}
$base[2]='/p:Config=Release'
$base[0]=$project
Check 'global-test-define' @('/p:DCC_Define=GAME_APPLICATION_BUILD%3BGAME_NATIVE_ABI_TESTS') $false
Check 'global-probe-define' @('/p:DCC_Define=GAME_APPLICATION_BUILD%3BGAME_EXAMPLE_PROBE') $false
Check 'release-with-debug-define' @('/p:DCC_Define=GAME_APPLICATION_BUILD%3BDEBUG') $false
Check 'release-with-both-defines' @('/p:DCC_Define=GAME_APPLICATION_BUILD%3BDEBUG%3BRELEASE') $false
Check 'release-without-configuration-define' @('/p:DCC_Define=GAME_APPLICATION_BUILD') $false
$base[2]='/p:Config=Debug'
Check 'debug-with-release-define' @('/p:DCC_Define=GAME_APPLICATION_BUILD%3BRELEASE') $false
Check 'debug-with-both-defines' @('/p:DCC_Define=GAME_APPLICATION_BUILD%3BDEBUG%3BRELEASE') $false
Check 'debug-without-configuration-define' @('/p:DCC_Define=GAME_APPLICATION_BUILD') $false
$base[2]='/p:Config=Invalid'
Check 'unknown-configuration' @() $false
$base[2]='/p:Config=Release'
Check 'external-compiler-option' @('/p:DCC_AdditionalOptions=-DTEST') $false
Check 'external-compiler-args' @('/p:DCC_AdditionalArgs=-DTEST') $false
Check 'external-compiler-parameters' @('/p:DCC_AdditionalParameters=-DTEST') $false
Check 'canonical-current-unit-path' @('/p:DCC_UnitSearchPath=..\..\Cozy.Source\Cozy.Platform\..\Cozy.Platform') $true
Check 'canonical-absolute-include-path' @(('/p:DCC_IncludePath='+(Join-Path $root 'Cozy.Source\Cozy.Configuration'))) $true
Check 'parent-unit-path' @('/p:DCC_UnitSearchPath=..') $false
Check 'parent-include-path' @('/p:DCC_IncludePath=..') $false
Check 'mixed-parent-unit-path' @('/p:DCC_UnitSearchPath=.%3B..') $false
Check 'absolute-parent-include-path' @(('/p:DCC_IncludePath='+(Split-Path -Parent $root))) $false
Check 'foreign-object-path' @('/p:DCC_ObjPath=tests') $false
Check 'parent-object-path' @('/p:DCC_ObjPath=..') $false
Check 'wildcard-unit-path' @('/p:DCC_UnitSearchPath=.*') $false
Check 'foreign-unit-path'  @('/p:DCC_UnitSearchPath=tests') $false
Check 'foreign-include-path' @('/p:DCC_IncludePath=tests') $false
Check 'foreign-dcu-output' @('/p:DCC_DcuOutput=build\tests\native_probe_build') $false
Check 'foreign-exe-output' @('/p:DCC_ExeOutput=build\tests\native_probe_build') $false
$rootDcu=Join-Path $root 'IsolationSentinel.dcu'
if(Test-Path -LiteralPath $rootDcu){throw 'ISOLATION_SENTINEL_ALREADY_EXISTS'}
try{[IO.File]::WriteAllBytes($rootDcu,[byte[]](1,2,3,4));Check 'root-reused-dcu' @() $false}
finally{Remove-Item -LiteralPath $rootDcu -Force -ErrorAction SilentlyContinue}
$stale=Join-Path $root 'Cozy.Projects\Cozy.Client\dcu\IsolationSentinel.dcu'
[IO.File]::WriteAllBytes($stale,[byte[]](1,2,3,4));Check 'fresh-role-dcu' @() $true
if(Test-Path -LiteralPath $stale){throw 'ISOLATION_STALE_DCU_REUSED'}
$junctionPath=Join-Path $root 'Cozy.Projects\Cozy.Client\dcu'
$junctionTarget=Join-Path $temporaryRoot 'junction-target'
if(Test-Path -LiteralPath $junctionTarget){throw 'ISOLATION_JUNCTION_SENTINEL_ALREADY_EXISTS'}
if(@(Get-ChildItem -LiteralPath $junctionPath -Force).Count -ne 0){throw 'ISOLATION_JUNCTION_SOURCE_NOT_EMPTY'}
[IO.Directory]::CreateDirectory($junctionTarget)|Out-Null
$sentinel=Join-Path $junctionTarget 'must-survive.txt';[IO.File]::WriteAllText($sentinel,'owned test sentinel')
try {
 [IO.Directory]::Delete($junctionPath)
 $null=New-Item -ItemType Junction -Path $junctionPath -Target $junctionTarget
 Check 'output-junction-clean-refused' @() $false
 if(-not(Test-Path -LiteralPath $sentinel)){throw 'ISOLATION_JUNCTION_TARGET_WAS_CLEANED'}
} finally {
 if(Test-Path -LiteralPath $junctionPath){$item=Get-Item -LiteralPath $junctionPath -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){[IO.Directory]::Delete($junctionPath)}}
 [IO.Directory]::CreateDirectory($junctionPath)|Out-Null
 Remove-Item -LiteralPath $junctionTarget -Recurse -Force
}
Write-Output 'PASS negative evaluated-MSBuild properties and project-local fresh outputs'

# Exercise the compiler's own fatal guard, not only an evaluated MSBuild regex.
# This tiny probe is never a product artifact and never reuses product DCUs.
$dcc=Join-Path $env:BDS 'bin\dcc64.exe'
if(-not(Test-Path -LiteralPath $dcc -PathType Leaf)){throw 'ISOLATION_NATIVE_COMPILER_REQUIRED'}
$guardOut=Join-Path $temporaryRoot 'compiler-guard'
[IO.Directory]::CreateDirectory($guardOut)|Out-Null
$guardUnit=Join-Path $guardOut 'units'
[IO.Directory]::CreateDirectory($guardUnit)|Out-Null
$guardSource=Join-Path $root 'Cozy.Tests\Cozy.Platform\Cozy.CompilerDefineGuardProbe.dpr'
$defines=@([regex]::Matches((Get-Content -LiteralPath (Join-Path $root 'Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc') -Raw),'\{\$IFDEF\s+(GAME_[A-Z0-9_]*(?:TESTS|PROBE))\}')|ForEach-Object{$_.Groups[1].Value}|Sort-Object -Unique)
if($defines.Count -lt 5){throw 'ISOLATION_NATIVE_GUARDS_MISSING'}
$guardExe=Join-Path $guardOut 'Cozy.CompilerDefineGuardProbe.exe'
$log=& $dcc '-B' '-Q' '-DGAME_APPLICATION_BUILD;RELEASE' ('-E'+$guardOut) ('-N0'+$guardUnit) $guardSource 2>&1
if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $guardExe)){Write-Output ($log|Out-String);throw 'ISOLATION_COMPILER_POSITIVE_CONTROL_FAILED'}
Remove-Item -LiteralPath $guardExe -Force -ErrorAction SilentlyContinue
$log=& $dcc '-B' '-Q' '-DGAME_APPLICATION_BUILD;DEBUG' ('-E'+$guardOut) ('-N0'+$guardUnit) $guardSource 2>&1
if($LASTEXITCODE -ne 0 -or -not(Test-Path -LiteralPath $guardExe)){Write-Output ($log|Out-String);throw 'ISOLATION_COMPILER_DEBUG_POSITIVE_CONTROL_FAILED'}
foreach($configurationDefines in @('GAME_APPLICATION_BUILD','GAME_APPLICATION_BUILD;DEBUG;RELEASE')) {
 Remove-Item -LiteralPath $guardExe -Force -ErrorAction SilentlyContinue
 $log=& $dcc '-B' '-Q' ('-D'+$configurationDefines) ('-E'+$guardOut) ('-N0'+$guardUnit) $guardSource 2>&1
 $code=$LASTEXITCODE;Write-Output ($log|Out-String)
 if($code -eq 0 -or (Test-Path -LiteralPath $guardExe) -or ($log|Out-String) -notmatch 'Application build configuration'){throw 'ISOLATION_COMPILER_CONFIGURATION_NOT_REJECTED'}
}
foreach($define in $defines){
 $guardExe=Join-Path $guardOut 'Cozy.CompilerDefineGuardProbe.exe'
 Remove-Item -LiteralPath $guardExe -Force -ErrorAction SilentlyContinue
 $log=& $dcc '-B' '-Q' ('-DGAME_APPLICATION_BUILD;RELEASE;'+$define) ('-E'+$guardOut) ('-N0'+$guardUnit) $guardSource 2>&1
 $code=$LASTEXITCODE;Write-Output ($log|Out-String)
 if($code -eq 0 -or (Test-Path -LiteralPath $guardExe) -or ($log|Out-String) -notmatch 'forbidden in application builds') {throw ('ISOLATION_COMPILER_DEFINE_NOT_REJECTED_'+$define)}
 Write-Output ('PASS ACTUAL_DCC64_TEST_DEFINE_REJECTION '+$define)
}

} finally {
 if(Test-Path -LiteralPath $temporaryRoot){Remove-Item -LiteralPath $temporaryRoot -Recurse -Force}
}
