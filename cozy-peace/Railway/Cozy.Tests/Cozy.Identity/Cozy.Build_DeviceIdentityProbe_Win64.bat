@echo off
setlocal EnableExtensions DisableDelayedExpansion
for %%R in ("%~dp0..\..") do set "COZY_NATIVE_ROOT=%%~fR"
if not exist "%COZY_NATIVE_ROOT%\Cozy.Source\" exit /b 1
cd /d "%COZY_NATIVE_ROOT%"
set "COZY_SOURCE_PATHS=Cozy.Source\Cozy.Application;Cozy.Source\Cozy.Lifecycle;Cozy.Source\Cozy.Platform;Cozy.Source\Cozy.Security;Cozy.Source\Cozy.Protection;Cozy.Source\Cozy.Network;Cozy.Source\Cozy.Identity;Cozy.Source\Cozy.Integrity;Cozy.Source\Cozy.Crypto;Cozy.Source\Cozy.Overlay;Cozy.Source\Cozy.Handoff;Cozy.Source\Cozy.Configuration;Cozy.Tests\Cozy.Build;Cozy.Tests\Cozy.Configuration;Cozy.Tests\Cozy.Crypto;Cozy.Tests\Cozy.FaultInjection;Cozy.Tests\Cozy.Handoff;Cozy.Tests\Cozy.Identity;Cozy.Tests\Cozy.Integrity;Cozy.Tests\Cozy.Lifecycle;Cozy.Tests\Cozy.Network;Cozy.Tests\Cozy.Overlay;Cozy.Tests\Cozy.Platform;Cozy.Tests\Cozy.Protocol;Cozy.Tests\Cozy.Security;Cozy.Tests\Cozy.Startup"
if errorlevel 1 exit /b 1
if not exist "%BDS%\bin\dcc64.exe" goto failed
set "DEVICE_PROBE_OUT=%CD%\build\tests\device-identity"
if not exist "%DEVICE_PROBE_OUT%" mkdir "%DEVICE_PROBE_OUT%"
if not exist "%DEVICE_PROBE_OUT%\units" mkdir "%DEVICE_PROBE_OUT%\units"
"%BDS%\bin\dcc64.exe" -B -Q -$R+ -$Q+ -D"RELEASE;GAME_DEVICE_IDENTITY_PROBE" -U"%COZY_SOURCE_PATHS%" -I"%COZY_SOURCE_PATHS%" -O"Cozy.BuildOutputs\Cozy.ImGui" -E"%DEVICE_PROBE_OUT%" -N0"%DEVICE_PROBE_OUT%\units" "Cozy.Tests\Cozy.Identity\Cozy.DeviceIdentityProbe.dpr"
if errorlevel 1 goto failed
node "..\Relay Server\tests\devices\peace.verify-device-identity-native.js" "%DEVICE_PROBE_OUT%\Cozy.DeviceIdentityProbe.exe" %1
if errorlevel 1 goto failed
exit /b 0
:failed
echo ERROR: Device identity native probe failed. No hardware verification was recorded.
exit /b 1
