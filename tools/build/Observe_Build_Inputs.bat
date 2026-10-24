@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Usage: Observe_Build_Inputs.bat [/nopause]
set "GAME_TOOL_RESULT=1"
set "GAME_TOOL_PAUSE=1"
if /i "%~1"=="/nopause" set "GAME_TOOL_PAUSE=0"
if /i "%~2"=="/nopause" set "GAME_TOOL_PAUSE=0"
echo Usage: Observe_Build_Inputs.bat [/nopause]
if not "%~1"=="" if /i not "%~1"=="/nopause" goto usage
if not "%~2"=="" goto usage
if not exist "%~dp0..\..\ci\toolchain\peace.build-input-lock.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
if not defined BDS goto missing_bds
if not exist "%BDS%\bin\dcc64.exe" goto missing_bds
node.exe "%~dp0..\..\ci\toolchain\peace.build-input-lock.js" observe "%~dp0..\..\..\Railway" "%~dp0..\.." "%BDS%" "%~dp0..\observed-build-inputs.json"
set "GAME_TOOL_RESULT=%errorlevel%"
echo Observation records actual files only; independent review is required before approval.
goto finish
:missing_bds
echo ERROR: BDS must identify the actual RAD Studio classic Win64 installation.
echo Run from its command prompt, or set BDS before running this BAT.
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
