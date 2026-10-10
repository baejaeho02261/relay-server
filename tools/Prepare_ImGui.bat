@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Run before rebuilding A/B/O. The audited object is not a rebuilt EXE.
rem Usage: Prepare_ImGui.bat [/nopause]
set "GCIM_EXIT=1"
set "GCIM_PAUSE=1"
set "GCIM_PUSHED="
if /i "%~1"=="/nopause" set "GCIM_PAUSE=0"
if not "%~1"=="" if /i not "%~1"=="/nopause" goto usage
if not "%~2"=="" goto usage
for %%D in ("%~dp0..\..\GameConnect_Win64") do set "GCIM_NATIVE=%%~fD"
if not exist "%GCIM_NATIVE%\imgui\Build_ImGui_Win64.bat" goto bad_layout
pushd "%GCIM_NATIVE%"
if errorlevel 1 goto directory_failed
set "GCIM_PUSHED=1"
if not defined BDS goto autodiscover
call imgui\Build_ImGui_Win64.bat "%BDS%"
if errorlevel 1 goto build_failed
goto copy_object
:autodiscover
call imgui\Build_ImGui_Win64.bat /nopause
if errorlevel 1 goto build_failed
:copy_object
if not exist "imgui\obj\Win64\game_imgui_bridge.o" goto build_failed
copy /b /y "imgui\obj\Win64\game_imgui_bridge.o" "game_imgui_bridge.o"
if errorlevel 1 goto copy_failed
"%SystemRoot%\System32\fc.exe" /b "imgui\obj\Win64\game_imgui_bridge.o" "game_imgui_bridge.o" >nul
if errorlevel 1 goto copy_failed
echo SUCCESS: ImGui object was audited, copied and byte-compared.
echo Next: Rebuild A/B/O in Win64 Release, then run Create_Approval and Check_Approval.
echo Finally run Create_Release_Manifest for those FINAL EXEs.
set "GCIM_EXIT=0"
goto finish
:copy_failed
if exist "game_imgui_bridge.o" del /q "game_imgui_bridge.o"
echo ERROR: object copy or verification failed. Stop the Delphi build.
goto finish
:build_failed
echo ERROR: ImGui preparation failed. Stop the Delphi build.
echo Review GameConnect_Win64\imgui\imgui-build.log.
goto finish
:bad_layout
echo ERROR: place this BAT in GameWeb\tools, with GameConnect_Win64 beside GameWeb.
goto finish
:directory_failed
echo ERROR: cannot enter the native project folder.
goto finish
:usage
echo Usage: Prepare_ImGui.bat [/nopause]
:finish
if defined GCIM_PUSHED popd
echo.
if "%GCIM_PAUSE%"=="1" pause
endlocal & exit /b %GCIM_EXIT%
