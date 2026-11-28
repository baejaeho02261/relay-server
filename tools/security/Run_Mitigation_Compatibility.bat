@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GCMC_EXIT=1"
set "GCMC_PAUSE=0"
if "%~1"=="" set "GCMC_PAUSE=1"
if not exist "%~dp0spacex.mitigation-compatibility.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
set "NODE_OPTIONS="
set "NODE_REPL_EXTERNAL_MODULE="
node.exe "%~dp0spacex.mitigation-compatibility.js" %*
set "GCMC_EXIT=%ERRORLEVEL%"
goto finish
:missing_helper
echo ERROR: Restore the matching spacex.mitigation-compatibility.js beside this BAT.
goto finish
:missing_node
echo ERROR: node.exe was not found in PATH.
:finish
echo.
if "%GCMC_PAUSE%"=="1" pause
endlocal & exit /b %GCMC_EXIT%
