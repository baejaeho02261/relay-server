@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Usage: Test_Server_1-5.bat [/nopause]
set "GAME_TOOL_RESULT=1"
set "GAME_TOOL_PAUSE=1"
if /i "%~1"=="/nopause" set "GAME_TOOL_PAUSE=0"
if /i "%~2"=="/nopause" set "GAME_TOOL_PAUSE=0"
echo Usage: Test_Server_1-5.bat [/nopause]
if not "%~1"=="" if /i not "%~1"=="/nopause" goto usage
if not "%~2"=="" goto usage
if not exist "%~dp0..\..\tests\protocol\peace.run-server-contracts-1-5.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
node.exe "%~dp0..\..\tests\protocol\peace.run-server-contracts-1-5.js" "%~dp0..\.."
set "GAME_TOOL_RESULT=%errorlevel%"
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
