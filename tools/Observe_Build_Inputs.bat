@echo off
setlocal
cd /d "%~dp0"
if not defined BDS (
  echo ERROR: run from a RAD Studio classic Win64 command prompt.
  pause
  exit /b 1
)
node "..\ci\build-input-lock.js" observe "..\..\GameConnect_Win64" ".." "%BDS%" "observed-build-inputs.json"
set "GAME_TOOL_RESULT=%errorlevel%"
echo This only records actual inputs. Review against trusted compiler and SDK installation before approval.
pause
exit /b %GAME_TOOL_RESULT%
