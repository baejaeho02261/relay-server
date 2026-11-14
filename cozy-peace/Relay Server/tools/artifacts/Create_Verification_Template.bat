@echo off
setlocal EnableExtensions DisableDelayedExpansion
where node.exe >nul 2>&1
if errorlevel 1 goto missing_node
if "%~1"=="" goto interactive
if "%~4"=="" goto usage
if not "%~5"=="" goto usage
node.exe "%~dp0peace.verification-report.js" prepare "%~f1" "%~f2" "%~f3" "%~f4"
set "GAME_VERIFICATION_EXIT=%errorlevel%"
goto done
:interactive
node.exe "%~dp0peace.verification-report.js" prepare
set "GAME_VERIFICATION_EXIT=%errorlevel%"
goto done
:missing_node
echo ERROR: node.exe is required.
set "GAME_VERIFICATION_EXIT=1"
goto done
:usage
echo Usage: Create_Verification_Template.bat "CONTEXT.json" "A.exe" "B.exe" "O.exe"
set "GAME_VERIFICATION_EXIT=2"
:done
echo Exit code: %GAME_VERIFICATION_EXIT%
pause
endlocal & exit /b %GAME_VERIFICATION_EXIT%
