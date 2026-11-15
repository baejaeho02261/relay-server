@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GAME_OVERLAY_ENV_PROBE="
set "GAME_OVERLAY_ENV_NOPAUSE="
:args
if "%~1"=="" goto parsed
if /i "%~1"=="/nopause" goto nopause
if defined GAME_OVERLAY_ENV_PROBE goto usage
set "GAME_OVERLAY_ENV_PROBE=%~1"
shift
goto args
:nopause
set "GAME_OVERLAY_ENV_NOPAUSE=1"
shift
goto args
:parsed
pushd "%~dp0.."
if errorlevel 1 exit /b 1
where node.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: Node.js is required.
  goto failed
)
if defined GAME_OVERLAY_ENV_PROBE goto run
set "GAME_OVERLAY_ENV_PROBE=%~dp0..\..\..\Railway\build\tests\manual-ide\Cozy.OverlayEnvironmentProbe.exe"
if exist "%GAME_OVERLAY_ENV_PROBE%" goto run
echo Build tests\cozy.manual-ide\cozy.OverlayEnvironmentProbe.dproj in the RAD Studio IDE: Win64 Release.
set /p "GAME_OVERLAY_ENV_PROBE=Full path to cozy.OverlayEnvironmentProbe.exe: "
:run
set "GAME_OVERLAY_ENV_PROBE=%GAME_OVERLAY_ENV_PROBE:"=%"
node "%~dp0peace.overlay-environment.js" run "%GAME_OVERLAY_ENV_PROBE%"
set "GAME_OVERLAY_ENV_EXIT=%ERRORLEVEL%"
popd
if not defined GAME_OVERLAY_ENV_NOPAUSE pause
exit /b %GAME_OVERLAY_ENV_EXIT%
:failed
popd
if not defined GAME_OVERLAY_ENV_NOPAUSE pause
exit /b 1
:usage
echo Usage: Run_Overlay_Environment.bat ["ABSOLUTE_cozy.OverlayEnvironmentProbe.exe"] [/nopause]
exit /b 1
