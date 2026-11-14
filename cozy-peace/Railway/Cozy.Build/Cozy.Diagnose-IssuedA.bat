@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Cozy.Diagnose-IssuedA.ps1" -LauncherPath "%~1"
pause
endlocal
