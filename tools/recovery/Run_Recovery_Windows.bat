@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "RECOVERY_INPUT=%~1"
set "RECOVERY_PAUSE=1"
if /i "%~1"=="/nopause" (set "RECOVERY_PAUSE=0" & set "RECOVERY_INPUT=")
if /i "%~2"=="/nopause" set "RECOVERY_PAUSE=0"
where pwsh.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: PowerShell 7 x64 is required. Use the original Windows user and device.
  set "RECOVERY_EXIT=1"
  goto done
)
pwsh.exe -NoLogo -NoProfile -File "%~dp0..\runtime\recovery-windows.ps1" -InputFile "%RECOVERY_INPUT%"
set "RECOVERY_EXIT=%ERRORLEVEL%"
:done
if "%RECOVERY_PAUSE%"=="1" pause
exit /b %RECOVERY_EXIT%
