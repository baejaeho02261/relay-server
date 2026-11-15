@echo off
setlocal EnableExtensions DisableDelayedExpansion
where node.exe >nul 2>&1
if errorlevel 1 goto missing_node
if not "%~2"=="" goto usage
if "%~1"=="" goto interactive
node.exe "%~dp0peace.verification-report.js" finalize "%~f1"
set "GAME_VERIFICATION_EXIT=%errorlevel%"
goto done
:interactive
node.exe "%~dp0peace.verification-report.js" finalize
set "GAME_VERIFICATION_EXIT=%errorlevel%"
goto done
:missing_node
echo ERROR: node.exe is required.
set "GAME_VERIFICATION_EXIT=1"
goto done
:usage
echo Usage: Create_Verification_Report.bat "verification-input.json"
set "GAME_VERIFICATION_EXIT=2"
:done
echo Exit code: %GAME_VERIFICATION_EXIT%
pause
endlocal & exit /b %GAME_VERIFICATION_EXIT%
