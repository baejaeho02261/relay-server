@echo off
setlocal
set "INPUT_FILE=%~f1"
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: Check_Recovery_State.bat "recovery-witness-input.json"
  echo Stop the server first. The native writer lock is never bypassed.
  exit /b 2
)
node "%~dp0recovery-maintenance.js" check "%INPUT_FILE%"
exit /b %errorlevel%
