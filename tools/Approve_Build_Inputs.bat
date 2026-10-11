@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: Approve_Build_Inputs.bat EXPECTED_SHA512_FROM_INDEPENDENT_REVIEW
  echo This pins reviewed bytes; it does not certify the compiler vendor or run Windows tests.
  pause
  exit /b 1
)
node "..\ci\approve-build-inputs.js" "observed-build-inputs.json" "%~1" "reviewed-build-inputs.json"
set "GAME_TOOL_RESULT=%errorlevel%"
pause
exit /b %GAME_TOOL_RESULT%
