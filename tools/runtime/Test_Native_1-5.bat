@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Usage: Test_Native_1-5.bat [/nopause]
set "GAME_TOOL_RESULT=1"
set "GAME_TOOL_PAUSE=1"
if /i "%~1"=="/nopause" set "GAME_TOOL_PAUSE=0"
if /i "%~2"=="/nopause" set "GAME_TOOL_PAUSE=0"
echo Usage: Test_Native_1-5.bat [/nopause]
if not "%~1"=="" if /i not "%~1"=="/nopause" goto usage
if not "%~2"=="" goto usage
if not exist "%~dp0..\..\tools\windows\Invoke-NativeContracts1To5.ps1" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
"%SystemRoot%\System32\where.exe" pwsh.exe >nul 2>&1
if errorlevel 1 goto missing_pwsh
if not defined BDS goto missing_bds
if not exist "%BDS%\bin\dcc64.exe" goto missing_bds
"%SystemRoot%\System32\where.exe" cl.exe >nul 2>&1
if errorlevel 1 goto missing_sdk
pwsh.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0..\..\tools\windows\Invoke-NativeContracts1To5.ps1" -ResultsDirectory "%~dp0.." -BdsRoot "%BDS%"
set "GAME_TOOL_RESULT=%errorlevel%"
goto finish
:missing_pwsh
echo ERROR: PowerShell 7 x64 is required. No native checks were executed.
set "GAME_TOOL_RESULT=2"
goto finish
:missing_bds
echo ERROR: BDS must identify the actual RAD Studio classic Win64 installation.
echo Run from its command prompt, or set BDS before running this BAT.
set "GAME_TOOL_RESULT=2"
goto finish
:missing_sdk
echo ERROR: cl.exe is missing. Use an x64 Native Tools command prompt with BDS set.
echo Native ABI checks compare Delphi with the installed Microsoft Windows SDK.
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
