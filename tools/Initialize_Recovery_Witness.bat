@echo off
setlocal
set "INPUT_FILE=%~f1"
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: Initialize_Recovery_Witness.bat "recovery-witness-input.json"
  echo Stop the server first. Enrollment never resets an existing witness.
  exit /b 2
)
node "%~dp0recovery-maintenance.js" enroll "%INPUT_FILE%"
exit /b %errorlevel%
