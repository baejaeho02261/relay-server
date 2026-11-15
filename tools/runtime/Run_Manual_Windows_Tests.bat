@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "MANUAL_NOPAUSE="
set "MANUAL_INPUT="
if /i "%~1"=="/nopause" (set "MANUAL_NOPAUSE=1") else (set "MANUAL_INPUT=%~1")
if /i "%~2"=="/nopause" set "MANUAL_NOPAUSE=1"
where pwsh.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: PowerShell 7 x64 is required. No Delphi command-line compiler is needed.
  set "MANUAL_EXIT=1"
  goto done
)
pwsh.exe -NoLogo -NoProfile -File "%~dp0manual-windows-tests.ps1" -InputFile "%MANUAL_INPUT%"
set "MANUAL_EXIT=%ERRORLEVEL%"
:done
if not defined MANUAL_NOPAUSE pause
exit /b %MANUAL_EXIT%
