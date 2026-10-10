Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7) { throw 'CI_WINDOWS_POWERSHELL7_X64_REQUIRED' }
if (-not ('GameCi.WindowsJob' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'WindowsJob.cs') }
function New-CiPrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw 'CI_DIRECTORY_MUST_BE_NEW' }
    [IO.Directory]::CreateDirectory($Path) | Out-Null
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true,$false)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($who in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($who,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    [IO.File]::WriteAllText((Join-Path $Path 'ci-owned-marker'),'GAME_WINDOWS_CI_V1')
}
function Get-CiEnvironment([string]$PrivateTemp) {
    $clean = @{}
    foreach ($name in @('SystemRoot','windir','ComSpec','PATH','PATHEXT','OS','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE','USERPROFILE','APPDATA','LOCALAPPDATA','ProgramData','ProgramFiles','ProgramFiles(x86)','ProgramW6432','BDS','BDSCOMMONDIR','VisualStudioVersion','VSINSTALLDIR','VCINSTALLDIR','VCToolsInstallDir','WindowsSdkDir','WindowsSDKVersion','UniversalCRTSdkDir','UCRTVersion','INCLUDE','LIB','LIBPATH')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($null -ne $value) { $clean[$name] = $value }
    }
    $clean['TEMP']=$PrivateTemp; $clean['TMP']=$PrivateTemp
    $clean['DATA_DIR']=(Join-Path $PrivateTemp 'never-production-data')
    $clean['HA_ENABLED']='0'; $clean['NPM_CONFIG_USERCONFIG']=(Join-Path $PrivateTemp 'empty.npmrc')
    [IO.File]::WriteAllText($clean['NPM_CONFIG_USERCONFIG'],'')
    return $clean
}
function Read-CiJson([string]$File) { return Get-Content -LiteralPath $File -Raw | ConvertFrom-Json -AsHashtable }
function Write-CiJson([string]$File,$Value) { [IO.File]::WriteAllText($File,($Value|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false)) }
function Assert-CiOwnedPath([string]$Path,[string]$Root) {
    $full=[IO.Path]::GetFullPath($Path);$base=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    if (-not $full.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'CI_PATH_OUTSIDE_OWNED_ROOT' }
    return $full
}
