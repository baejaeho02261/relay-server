@echo off
setlocal
where pwsh.exe >nul 2>nul
if errorlevel 1 (echo PowerShell 7 x64 is required. & exit /b 1)
pwsh.exe -NoLogo -NoProfile -File "%~dp0..\windows\Check-WindowsEnvironment.ps1"
set "COZY_ENV_EXIT=%errorlevel%"
if /i not "%~1"=="/nopause" pause
endlocal & exit /b %COZY_ENV_EXIT%
