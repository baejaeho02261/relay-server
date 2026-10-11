@echo off
setlocal
cd /d "%~dp0"
where pwsh.exe >nul 2>&1
if errorlevel 1 (
  echo PowerShell 7 x64 is required. No native checks were executed.
  exit /b 2
)
pwsh.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0..\ci\Invoke-NativeContracts6To10.ps1" -ResultsDirectory "%CD%"
exit /b %errorlevel%
