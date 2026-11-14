@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem No arguments: interactive, including Explorer double-click. The IDE passes
rem its BDS directory explicitly and must never stop for keyboard input.
set "GAME_IMGUI_INTERACTIVE=1"
if not "%~1"=="" set "GAME_IMGUI_INTERACTIVE=0"
if /i "%~1"=="/nopause" goto arguments_ready
if not "%~1"=="" set "BDS=%~1"
:arguments_ready
set "GAME_IMGUI_LOG=%~dp0Cozy.ImGui.Build.log"
set "COZY_IMGUI_OBJECT_DIR=%~dp0..\..\Cozy.BuildOutputs\Cozy.ImGui"
set "GAME_IMGUI_EXIT=1"
pushd "%~dp0.."
if errorlevel 1 goto directory_failed

echo Preparing embedded Dear ImGui. Compiler output follows when complete.
echo Build log: "%GAME_IMGUI_LOG%"
type nul >"%GAME_IMGUI_LOG%" 2>nul
if errorlevel 1 goto log_failed
call :build >"%GAME_IMGUI_LOG%" 2>&1
set "GAME_IMGUI_EXIT=%ERRORLEVEL%"
type "%GAME_IMGUI_LOG%"
echo Build log saved: "%GAME_IMGUI_LOG%"
popd
goto finish

:log_failed
echo ERROR: Cannot write the ImGui build log: "%GAME_IMGUI_LOG%"
popd
goto finish

:directory_failed
echo ERROR: Cannot enter the ImGui source directory: "%~dp0"
goto finish

:finish
if "%GAME_IMGUI_INTERACTIVE%"=="1" (
  echo.
  echo Press any key to close this build window.
  pause >nul
)
exit /b %GAME_IMGUI_EXIT%

:build

set "GAME_IMGUI_STAGE=remove previous output"
rem The Pascal unit uses an explicit relative $L path into the isolated output
rem directory. Only one audited object is published, never an adjacent duplicate.
if exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o" del /q "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o"
if exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o" del /q "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o"
if exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o" goto failed
if exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o" goto failed

set "GAME_IMGUI_STAGE=validate C/Pascal ABI source contract"
where.exe node.exe >nul 2>&1
if errorlevel 1 (
  echo ERROR: Node.js is required to validate the C/Pascal ImGui ABI before building.
  echo Install the pinned Node.js version declared by Relay Server/package.json.
  goto failed
)
node "Cozy.Build\Cozy.Check-ImGui-Abi.js"
if errorlevel 1 goto failed

set "GAME_IMGUI_STAGE=locate RAD Studio classic Win64 C++ tools"
if not defined BDS call :find_rad_studio
if not defined BDS (
  echo ERROR: RAD Studio 13.1 was not found and BDS is not set.
  echo Open the RAD Studio 13.1 Command Prompt and run this script again.
  echo Or pass the RAD Studio installation directory as the first argument.
  goto failed
)
set "GAME_IMGUI_COMPILER=%BDS%\bin\bcc64.exe"
if defined GAME_IMGUI_BCC64 set "GAME_IMGUI_COMPILER=%GAME_IMGUI_BCC64%"
if not exist "%GAME_IMGUI_COMPILER%" (
  echo ERROR: Classic C++Builder Win64 bcc64.exe was not found:
  echo "%GAME_IMGUI_COMPILER%"
  echo Install the classic C++ Win64 tools. Delphi alone cannot compile ImGui C++.
  echo bcc64x is not interchangeable with this dcc64 static-object build.
  goto failed
)
if not exist "%BDS%\include\windows\sdk\d3d11.h" (
  echo ERROR: The Windows SDK headers were not found under the selected BDS:
  echo "%BDS%\include\windows\sdk\d3d11.h"
  goto failed
)

if not exist "%BDS%\include\windows\sdk\dcomp.h" (
  echo ERROR: DirectComposition SDK header dcomp.h is required for smooth transparent corners.
  goto failed
)
if not exist "%BDS%\include\windows\sdk\dxgi1_2.h" (
  echo ERROR: DXGI 1.2 SDK headers are required for the composition flip chain.
  goto failed
)

set "GAME_IMGUI_STAGE=create object output directory"
if not exist "%COZY_IMGUI_OBJECT_DIR%" mkdir "%COZY_IMGUI_OBJECT_DIR%"
if not exist "%COZY_IMGUI_OBJECT_DIR%" goto failed
set "GAME_IMGUI_STAGE=compile ABI type and field layout assertions"
"%GAME_IMGUI_COMPILER%" -std=c++11 -fsyntax-only -isystem "%BDS%\include" -isystem "%BDS%\include\dinkumware64" -isystem "%BDS%\include\windows\crtl" -isystem "%BDS%\include\windows\sdk" "Cozy.Tests\Cozy.Abi\Cozy.test_imgui_abi_layout.cpp"
if errorlevel 1 goto failed

set "GAME_IMGUI_STAGE=compile C++ bridge"
rem Keep immutable UI arrays in separate ELF data sections. This changes only
rem object placement: all current posters, blur pixels and render code remain.
echo Building embedded Dear ImGui with classic bcc64 ELF and separate data sections...
"%GAME_IMGUI_COMPILER%" -c -std=c++11 -O2 -fdata-sections -fno-exceptions -fno-rtti -fno-builtin -fno-use-cxa-atexit -I"Cozy.Vendor\Cozy.Core" -I"Cozy.Vendor\Cozy.Backends" -I"Cozy.Bridge\Cozy.Core" -isystem "%BDS%\include" -isystem "%BDS%\include\dinkumware64" -isystem "%BDS%\include\windows\crtl" -isystem "%BDS%\include\windows\sdk" -o "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o" "Cozy.Bridge\Cozy.Core\Cozy.game_imgui_bridge.cpp"
if errorlevel 1 goto failed
if not exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o" goto failed

set "GAME_IMGUI_STAGE=audit ELF64 object and required C exports"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "Cozy.Build\Cozy.Audit-Object.ps1" -Path "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o"
if errorlevel 1 goto failed
set "GAME_IMGUI_STAGE=publish audited object"
move /y "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o" "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o" >nul
if errorlevel 1 goto failed
if not exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o" goto failed
echo ImGui object ready: "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o"
exit /b 0

:failed
if exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o" del /q "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.pending.o"
if exist "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o" del /q "%COZY_IMGUI_OBJECT_DIR%\Cozy.game_imgui_bridge.o"
echo ERROR: ImGui preparation failed at stage: %GAME_IMGUI_STAGE%
echo Delphi compilation must stop. Fix the preceding error and rebuild Cozy.Overlay.dproj.
exit /b 1

:find_rad_studio
rem Only inspect this RAD Studio version's registered installation roots.
rem An explicit argument or an existing BDS environment value always wins.
for %%K in ("HKCU\Software\Embarcadero\BDS\37.0" "HKLM\Software\Embarcadero\BDS\37.0") do (
  for /f "tokens=2,*" %%A in ('reg.exe query "%%~K" /v RootDir /reg:32 2^>nul') do if /i "%%A"=="REG_SZ" if not defined BDS set "BDS=%%B"
  for /f "tokens=2,*" %%A in ('reg.exe query "%%~K" /v RootDir /reg:64 2^>nul') do if /i "%%A"=="REG_SZ" if not defined BDS set "BDS=%%B"
)
if not defined BDS if exist "%ProgramFiles(x86)%\Embarcadero\Studio\37.0\bin\bcc64.exe" set "BDS=%ProgramFiles(x86)%\Embarcadero\Studio\37.0"
if not defined BDS if exist "%ProgramFiles%\Embarcadero\Studio\37.0\bin\bcc64.exe" set "BDS=%ProgramFiles%\Embarcadero\Studio\37.0"
exit /b 0
