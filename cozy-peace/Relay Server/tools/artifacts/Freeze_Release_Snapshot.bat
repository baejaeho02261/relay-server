@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0..\.."
if errorlevel 1 exit /b 1
node.exe "%~dp0peace.release-snapshot.js" %*
set "RESULT=%ERRORLEVEL%"
echo This optional archive operation does not approve a release.
pause
endlocal & exit /b %RESULT%
