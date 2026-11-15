@echo off
setlocal
cd /d "%~dp0.."
set "ROTATION_INPUT=%~1"
if not defined ROTATION_INPUT set "ROTATION_INPUT=%~dp0..\transport-key-retire-input.json"
if not exist "%ROTATION_INPUT%" (
  echo ERROR: Input JSON is missing: "%ROTATION_INPUT%"
  echo Stop the server and supply version, dataDirectory, actor and request.
  echo This tool never replaces client pins automatically.
  pause
  exit /b 1
)
node "%~dp0peace.transport-key-maintenance.js" retire "%ROTATION_INPUT%"
set "ROTATION_EXIT=%ERRORLEVEL%"
echo Results are saved beside this BAT. Restart the server after a successful change.
pause
exit /b %ROTATION_EXIT%
