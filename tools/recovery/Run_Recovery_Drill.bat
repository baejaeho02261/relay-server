@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Run_Recovery_Drill.bat backup "INPUT.json" "NEW-RESULT.json" [/nopause]
rem Run_Recovery_Drill.bat selftest "NEW-RESULT.json" [/nopause]
set "GAME_TOOL_RESULT=1"
set "GAME_TOOL_PAUSE=1"
if /i "%~3"=="/nopause" set "GAME_TOOL_PAUSE=0"
if /i "%~4"=="/nopause" set "GAME_TOOL_PAUSE=0"
echo Offline isolated recovery drill. No server, CI key, Windows binary or physical TPM is exercised.
echo Use a complete stopped-server backup or coherent snapshot, never a live DATA_DIR.
if not exist "%~dp0peace.recovery-drill.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
if /i "%~1"=="selftest" goto selftest
if /i not "%~1"=="backup" goto usage
if "%~2"=="" goto usage
if "%~3"=="" goto usage
if /i "%~3"=="/nopause" goto usage
if not "%~4"=="" if /i not "%~4"=="/nopause" goto usage
if not "%~5"=="" goto usage
node.exe "%~dp0peace.recovery-drill.js" backup "%~f2" "%~f3"
set "GAME_TOOL_RESULT=%errorlevel%"
goto finish
:selftest
if "%~2"=="" goto usage
if /i "%~2"=="/nopause" goto usage
if not "%~3"=="" if /i not "%~3"=="/nopause" goto usage
if not "%~4"=="" goto usage
node.exe "%~dp0peace.recovery-drill.js" selftest "%~f2"
set "GAME_TOOL_RESULT=%errorlevel%"
goto finish
:missing_node
echo ERROR: node.exe is required. Install the project-supported Node.js and dependencies.
goto finish
:missing_helper
echo ERROR: Matching recovery drill sources are missing.
goto finish
:usage
echo Usage: Run_Recovery_Drill.bat backup "INPUT.json" "NEW-RESULT.json" [/nopause]
echo Usage: Run_Recovery_Drill.bat selftest "NEW-RESULT.json" [/nopause]
echo The result path must be new and outside both source backup directories.
set "GAME_TOOL_RESULT=2"
:finish
echo Exit code: %GAME_TOOL_RESULT%
if "%GAME_TOOL_PAUSE%"=="1" pause
endlocal & exit /b %GAME_TOOL_RESULT%
