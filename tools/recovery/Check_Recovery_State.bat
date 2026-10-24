@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Usage: Check_Recovery_State.bat "INPUT.json" [/nopause]
set "GAME_TOOL_RESULT=1"
set "GAME_TOOL_PAUSE=1"
if /i "%~1"=="/nopause" set "GAME_TOOL_PAUSE=0"
if /i "%~2"=="/nopause" set "GAME_TOOL_PAUSE=0"
echo Usage: Check_Recovery_State.bat "INPUT.json" [/nopause]
echo Stop the server first. The native writer lock is never bypassed.
if "%~1"=="" goto missing_input
if /i "%~1"=="/nopause" goto missing_input
if not "%~2"=="" if /i not "%~2"=="/nopause" goto usage
if not "%~3"=="" goto usage
set "INPUT_FILE=%~f1"
if not exist "%INPUT_FILE%" goto missing_input
if not exist "%~dp0peace.recovery-maintenance.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
node.exe "%~dp0peace.recovery-maintenance.js" check "%INPUT_FILE%"
set "GAME_TOOL_RESULT=%errorlevel%"
goto finish
:missing_input
echo ERROR: Supply an explicit, completed input JSON. Example files are not operational configuration.
set "GAME_TOOL_RESULT=2"
goto finish
:missing_node
echo ERROR: node.exe was not found in PATH. Install the project-supported Node.js LTS.
goto finish
:missing_helper
echo ERROR: Required source file is missing. Restore the matching complete source package.
goto finish
:usage
echo ERROR: Invalid arguments. See the usage printed above.
:finish
echo Exit code: %GAME_TOOL_RESULT%
if "%GAME_TOOL_PAUSE%"=="1" pause
endlocal & exit /b %GAME_TOOL_RESULT%
