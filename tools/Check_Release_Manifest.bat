@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Place beside release-tools.js in GameWeb\tools.
rem Usage: Check_Release_Manifest.bat [A.exe B.exe O.exe [MANIFEST.json]]
rem No arguments: guided input and final pause. Arguments: no pause.
rem spec.json, deployment-policy.json and default release-manifest.json stay here.
set "GCRT_EXIT=1"
set "GCRT_PAUSE=0"
if "%~1"=="" set "GCRT_PAUSE=1"
if not exist "%~dp0release-tools.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
node.exe "%~dp0release-tools.js" check %*
set "GCRT_EXIT=%ERRORLEVEL%"
goto finish
:missing_helper
echo ERROR: place this BAT beside release-tools.js in the matching GameWeb\tools folder.
goto finish
:missing_node
echo ERROR: node.exe was not found in PATH. Use the GameWeb Node.js runtime.
:finish
echo.
if "%GCRT_PAUSE%"=="1" pause
endlocal & exit /b %GCRT_EXIT%
