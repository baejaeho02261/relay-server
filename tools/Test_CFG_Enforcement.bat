@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GAME_CFG_EXIT=1"
set "GAME_CFG_PAUSE=1"
if /i "%~1"=="/nopause" set "GAME_CFG_PAUSE=0"
if not "%~1"=="" if /i not "%~1"=="/nopause" goto usage
if not "%~2"=="" goto usage
if not exist "%~dp0cfg-enforcement.ps1" goto missing
"%SystemRoot%\System32\where.exe" pwsh.exe >nul 2>&1
if errorlevel 1 goto pwsh
pwsh.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0cfg-enforcement.ps1" -ResultsDirectory "%~dp0."
set "GAME_CFG_EXIT=%errorlevel%"
goto finish
:pwsh
echo ERROR: PowerShell 7 x64 is required. No CFG result was created.
goto finish
:missing
echo ERROR: Restore the complete matching source package. cfg-enforcement.ps1 is missing.
goto finish
:usage
echo Usage: Test_CFG_Enforcement.bat [/nopause]
goto finish
:finish
echo Exit code: %GAME_CFG_EXIT%
if "%GAME_CFG_PAUSE%"=="1" pause
endlocal & exit /b %GAME_CFG_EXIT%
