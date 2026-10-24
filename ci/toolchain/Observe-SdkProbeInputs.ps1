param([Parameter(Mandatory)][string]$OutputFile)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$cl=(Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$files=[ordered]@{};$count=0;$bytes=[int64]0
function Add([string]$Name,[string]$File){
 $s=Get-Item -LiteralPath $File
 if($s.PSIsContainer -or ($s.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $s.Length -gt 512MB){throw 'CI_SDK_PROBE_INPUT_INVALID'}
 $script:count++;$script:bytes+=$s.Length
 if($script:count -gt 100000 -or $script:bytes -gt 32GB){throw 'CI_SDK_PROBE_INPUT_LIMIT'}
 $files[$Name]=(Get-FileHash -LiteralPath $s.FullName -Algorithm SHA512).Hash.ToLowerInvariant()
}
Add 'tool/cl.exe' $cl
$compilerDirectory=Split-Path -Parent $cl
foreach($file in Get-ChildItem -LiteralPath $compilerDirectory -File|Where-Object{$_.Extension -in @('.exe','.dll')}|Sort-Object Name){Add ('tool/'+$file.Name) $file.FullName}
$index=0
foreach($root in ($env:INCLUDE -split ';'|Where-Object{$_.Trim()})){
 $base=(Resolve-Path -LiteralPath $root).ProviderPath.TrimEnd('\')+'\'
 foreach($file in Get-ChildItem -LiteralPath $root -Recurse -File|Sort-Object FullName){Add ('include/'+$index+'/'+$file.FullName.Substring($base.Length).Replace('\','/')) $file.FullName}
 $index++
}
if($index -eq 0){throw 'CI_SDK_INCLUDE_ROOTS_REQUIRED'}
$hash=[Security.Cryptography.SHA512]::Create()
try{$digest=[BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($files|ConvertTo-Json -Depth 3 -Compress)))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
$result=[ordered]@{version=1;kind='OBSERVED_INDEPENDENT_MSVC_ABI_PROBE_INPUTS_NOT_APPROVED_LOCK';compilerVersion=(Get-Item -LiteralPath $cl).VersionInfo.FileVersion;inputSha512=$digest;files=$files}
[IO.File]::WriteAllText($OutputFile,($result|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
Write-Output ('OBSERVED_SDK_PROBE_INPUTS SHA512='+$digest+' files='+$count+' (separate from approved classic BDS toolchain)')
