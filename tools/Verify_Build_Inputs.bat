@echo off
setlocal
cd /d "%~dp0"
if not defined BDS (
  echo ERROR: run from a RAD Studio classic Win64 command prompt.
  pause
  exit /b 1
)
node "..\ci\build-input-lock.js" verify "..\..\GameConnect_Win64" ".." "%BDS%" "reviewed-build-inputs.json" "verified-build-inputs.json"
set "GAME_TOOL_RESULT=%errorlevel%"
pause
exit /b %GAME_TOOL_RESULT%
