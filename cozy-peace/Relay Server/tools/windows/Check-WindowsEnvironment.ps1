$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not $IsWindows -or [IntPtr]::Size -ne 8 -or $PSVersionTable.PSVersion.Major -lt 7){throw 'WINDOWS_TEST_POWERSHELL7_X64_REQUIRED'}
$node=(Get-Command node.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
& $node --version
if($LASTEXITCODE -ne 0){throw 'WINDOWS_TEST_NODE_UNAVAILABLE'}
Write-Output ('PowerShell: '+$PSVersionTable.PSVersion.ToString())
Write-Output 'Environment check complete. No compiler, executable, signing key or production service was used.'
