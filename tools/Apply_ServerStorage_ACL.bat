@echo off
setlocal
set "INPUT_FILE=%~f1"
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: Apply_ServerStorage_ACL.bat "storage-acl-input.json"
  echo Stop the server first. Set the actual service SID and storage directories.
  exit /b 2
)
node "%~dp0storage-acl.js" apply "%INPUT_FILE%"
exit /b %errorlevel%
