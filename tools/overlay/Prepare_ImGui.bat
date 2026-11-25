@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Build the single audited central object before rebuilding A/B/O.
set "GCIM_EXIT=1"
set "GCIM_PAUSE=1"
set "GCIM_PUSHED="
if /i "%~1"=="/nopause" set "GCIM_PAUSE=0"
if not "%~1"=="" if /i not "%~1"=="/nopause" goto usage
if not "%~2"=="" goto usage
for %%D in ("%~dp0..\..\..\Desktop") do set "GCIM_NATIVE=%%~fD"
if not exist "%GCIM_NATIVE%\SpaceX.ImGui\SpaceX.Build\SpaceX.Build_ImGui_Win64.bat" goto bad_layout
pushd "%GCIM_NATIVE%"
if errorlevel 1 goto directory_failed
set "GCIM_PUSHED=1"
if not defined BDS goto autodiscover
call "SpaceX.ImGui\SpaceX.Build\SpaceX.Build_ImGui_Win64.bat" "%BDS%"
if errorlevel 1 goto build_failed
goto verify_object
:autodiscover
call "SpaceX.ImGui\SpaceX.Build\SpaceX.Build_ImGui_Win64.bat" /nopause
if errorlevel 1 goto build_failed
:verify_object
if not exist "SpaceX.ImGui\SpaceX.Objects\SpaceX.game_imgui_bridge.o" goto build_failed
echo SUCCESS: the audited object is available at SpaceX.ImGui\SpaceX.Objects.
echo Rebuild A/B/O in Win64 Release and review the final EXEs.
set "GCIM_EXIT=0"
goto finish
:build_failed
echo ERROR: ImGui preparation failed. Stop the Delphi build.
echo Review Desktop\SpaceX.ImGui\SpaceX.Build\SpaceX.ImGui.Build.log.
goto finish
:bad_layout
echo ERROR: the complete SpaceX source tree is required.
goto finish
:directory_failed
echo ERROR: cannot enter the native project folder.
goto finish
:usage
echo Usage: Prepare_ImGui.bat [/nopause]
:finish
if defined GCIM_PUSHED popd
if "%GCIM_PAUSE%"=="1" pause
endlocal & exit /b %GCIM_EXIT%
