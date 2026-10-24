@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Read-only files/approval/manifest inspection, no CI or compiler required.
rem Usage: Check_Manual_Release.bat [/pre-manifest] [/verify-build-inputs] [A.exe A.json B.exe B.json O.exe O.json]
rem /verify-build-inputs measures current BDS inputs against an existing reviewed record; no compiler is run.
set "GCMR_EXIT=1"
set "GCMR_PAUSE=0"
if "%~1"=="" set "GCMR_PAUSE=1"
if /i "%~1"=="/pre-manifest" if "%~2"=="" set "GCMR_PAUSE=1"
if /i "%~1"=="/verify-build-inputs" if "%~2"=="" set "GCMR_PAUSE=1"
if /i "%~1"=="/pre-manifest" if /i "%~2"=="/verify-build-inputs" if "%~3"=="" set "GCMR_PAUSE=1"
if /i "%~1"=="/verify-build-inputs" if /i "%~2"=="/pre-manifest" if "%~3"=="" set "GCMR_PAUSE=1"
if not exist "%~dp0peace.manual-release-check.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
set "NODE_OPTIONS="
set "NODE_REPL_EXTERNAL_MODULE="
node.exe "%~dp0peace.manual-release-check.js" %*
set "GCMR_EXIT=%ERRORLEVEL%"
goto finish
:missing_helper
echo ERROR: peace.manual-release-check.js is missing beside this BAT. Restore the complete matching tools folder.
goto finish
:missing_node
echo ERROR: node.exe was not found in PATH. Use the installed Relay Server Node.js runtime.
:finish
echo.
if "%GCMR_PAUSE%"=="1" pause
endlocal & exit /b %GCMR_EXIT%
