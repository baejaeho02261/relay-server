@echo off
setlocal
where pwsh.exe >nul 2>nul || (echo PowerShell 7 x64 is required. & exit /b 1)
pwsh.exe -NoLogo -NoProfile -File "%~dp0..\runtime\security-authority-windows-tests.ps1" %*
exit /b %errorlevel%
