@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem /nopause must be the first argument; other arguments are PowerShell named parameters.
rem Example: /nopause -CiKeyFile "C:\Private Keys\CI\ci-private.pem"
set "GC_CI_PAUSE=1"
set "GC_CI_EXIT=1"
if /i "%~1"=="/nopause" (
  set "GC_CI_PAUSE=0"
  shift
)
where pwsh.exe >nul 2>nul
if errorlevel 1 goto no_powershell
pwsh.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\build\ci-workflow.ps1" -Action environment %1 %2 %3 %4 %5 %6 %7 %8 %9
set "GC_CI_EXIT=%errorlevel%"
goto finish
:no_powershell
echo ERROR: Install PowerShell 7 x64 and reopen this command window. pwsh.exe was not found.
echo Windows PowerShell 5.1 is not sufficient for the actual Windows CI runner.
goto finish
:finish
echo.
if "%GC_CI_PAUSE%"=="1" pause
endlocal & exit /b %GC_CI_EXIT%
