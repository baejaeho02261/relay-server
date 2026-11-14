@echo off
setlocal EnableExtensions DisableDelayedExpansion
if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (
  echo ERROR: Windows PowerShell was not found.
  exit /b 1
)
if not exist "%~dp0Cozy.Build-All-Win64.ps1" (
  echo ERROR: Cozy.Build-All-Win64.ps1 is missing.
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0Cozy.Build-All-Win64.ps1" %*
set "COZY_BUILD_RESULT=%ERRORLEVEL%"
endlocal & exit /b %COZY_BUILD_RESULT%
