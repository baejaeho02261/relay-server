@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GC_CI_DIAG_PAUSE=1"
set "GC_CI_DIAG_EXIT=1"
if /i "%~1"=="/nopause" set "GC_CI_DIAG_PAUSE=0"
where pwsh.exe >nul 2>nul
if errorlevel 1 goto no_powershell
pwsh.exe -NoLogo -NoProfile -File "%~dp0Diagnose_CI_Runner.ps1"
set "GC_CI_DIAG_EXIT=%errorlevel%"
goto finish
:no_powershell
echo ERROR: PowerShell 7 x64 is required. pwsh.exe was not found.
:finish
echo.
echo Diagnostic exit code: %GC_CI_DIAG_EXIT%
if "%GC_CI_DIAG_PAUSE%"=="1" pause
endlocal & exit /b %GC_CI_DIAG_EXIT%
