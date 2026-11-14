@echo off
setlocal EnableExtensions DisableDelayedExpansion
for %%R in ("%~dp0..\..") do set "COZY_NATIVE_ROOT=%%~fR"
if not exist "%COZY_NATIVE_ROOT%\Cozy.Source\" exit /b 1
cd /d "%COZY_NATIVE_ROOT%"
set "COZY_SOURCE_PATHS=Cozy.Source\Cozy.Application;Cozy.Source\Cozy.Lifecycle;Cozy.Source\Cozy.Platform;Cozy.Source\Cozy.Security;Cozy.Source\Cozy.Protection;Cozy.Source\Cozy.Network;Cozy.Source\Cozy.Identity;Cozy.Source\Cozy.Integrity;Cozy.Source\Cozy.Crypto;Cozy.Source\Cozy.Overlay;Cozy.Source\Cozy.Handoff;Cozy.Source\Cozy.Configuration;Cozy.Tests\Cozy.Build;Cozy.Tests\Cozy.Configuration;Cozy.Tests\Cozy.Crypto;Cozy.Tests\Cozy.FaultInjection;Cozy.Tests\Cozy.Handoff;Cozy.Tests\Cozy.Identity;Cozy.Tests\Cozy.Integrity;Cozy.Tests\Cozy.Lifecycle;Cozy.Tests\Cozy.Network;Cozy.Tests\Cozy.Overlay;Cozy.Tests\Cozy.Platform;Cozy.Tests\Cozy.Protocol;Cozy.Tests\Cozy.Security;Cozy.Tests\Cozy.Startup"
if not defined BDS (
  echo Open the RAD Studio Command Prompt and run this file again.
  exit /b 1
)
call "%BDS%\bin\rsvars.bat"
if errorlevel 1 exit /b 1
call "Cozy.ImGui\Cozy.Build\Cozy.Build_ImGui_Win64.bat" "%BDS%"
if errorlevel 1 exit /b 1
if not exist "build\tests\api-probe" mkdir "build\tests\api-probe"
"%BDS%\bin\dcc64.exe" -B -Q -$R+ -$Q+ -U"%COZY_SOURCE_PATHS%" -I"%COZY_SOURCE_PATHS%" -O"Cozy.BuildOutputs\Cozy.ImGui" -E".\build\tests\api-probe" -N0".\build\tests\api-probe" "Cozy.Tests\Cozy.Platform\Cozy.ApiResolverProbe.dpr"
if errorlevel 1 exit /b 1
"build\tests\api-probe\Cozy.ApiResolverProbe.exe"
exit /b %errorlevel%
