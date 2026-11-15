@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "LIFECYCLE_NOPAUSE="
set "LIFECYCLE_INPUT=%~1"
if /i "%~1"=="/nopause" (set "LIFECYCLE_NOPAUSE=1" & set "LIFECYCLE_INPUT=")
if /i "%~2"=="/nopause" set "LIFECYCLE_NOPAUSE=1"
where pwsh.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: PowerShell 7 x64 is required. Build dedicated test projects in RAD Studio IDE first.
  set "LIFECYCLE_EXIT=1"
  goto done
)
pwsh.exe -NoLogo -NoProfile -File "%~dp0lifecycle-windows-tests.ps1" -InputFile "%LIFECYCLE_INPUT%"
set "LIFECYCLE_EXIT=%ERRORLEVEL%"
:done
if not defined LIFECYCLE_NOPAUSE pause
exit /b %LIFECYCLE_EXIT%
