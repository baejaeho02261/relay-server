@echo off
setlocal
cd /d "%~dp0"
set "ROTATION_INPUT=%~1"
if not defined ROTATION_INPUT set "ROTATION_INPUT=%~dp0transport-key-status-input.json"
if not exist "%ROTATION_INPUT%" (
  echo ERROR: Input JSON is missing: "%ROTATION_INPUT%"
  echo Stop the server and supply version, dataDirectory, actor and request.
  echo This tool never replaces client pins automatically.
  pause
  exit /b 1
)
node "%~dp0transport-key-maintenance.js" status "%ROTATION_INPUT%"
set "ROTATION_EXIT=%ERRORLEVEL%"
echo Results are saved beside this BAT. Restart the server after a successful change.
pause
exit /b %ROTATION_EXIT%
