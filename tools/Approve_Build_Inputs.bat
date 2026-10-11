@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Usage: Approve_Build_Inputs.bat [EXPECTED_SHA512_FROM_INDEPENDENT_REVIEW] [/nopause]
set "GAME_TOOL_RESULT=1"
set "GAME_TOOL_PAUSE=1"
if /i "%~1"=="/nopause" set "GAME_TOOL_PAUSE=0"
if /i "%~2"=="/nopause" set "GAME_TOOL_PAUSE=0"
echo Usage: Approve_Build_Inputs.bat [EXPECTED_SHA512_FROM_INDEPENDENT_REVIEW] [/nopause]
if not "%~2"=="" if /i not "%~2"=="/nopause" goto usage
if not "%~3"=="" goto usage
set "GAME_REVIEWED_DIGEST=%~1"
if /i "%~1"=="/nopause" set "GAME_REVIEWED_DIGEST="
if not exist "%~dp0..\ci\approve-build-inputs.js" goto missing_helper
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
if defined GAME_REVIEWED_DIGEST goto approve
if "%GAME_TOOL_PAUSE%"=="0" goto missing_digest
echo Enter the SHA-512 approved by independent review of the observed build inputs.
echo This is not a compiler authenticity check or Windows test PASS.
set /p "GAME_REVIEWED_DIGEST=Reviewed SHA-512: "
if not defined GAME_REVIEWED_DIGEST goto missing_digest
:approve
rem Pass prompted text through the environment, never as CMD executable text.
node.exe -e "const a=process.argv;process.argv=[process.execPath,a[1],a[2],process.env.GAME_REVIEWED_DIGEST,a[3]];require(a[1]);" "%~dp0..\ci\approve-build-inputs.js" "%~dp0observed-build-inputs.json" "%~dp0reviewed-build-inputs.json"
set "GAME_TOOL_RESULT=%errorlevel%"
goto finish
:missing_digest
echo ERROR: An independently reviewed 128-character lowercase SHA-512 is required.
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
