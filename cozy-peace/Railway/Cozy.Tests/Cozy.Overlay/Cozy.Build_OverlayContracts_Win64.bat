@echo off
setlocal EnableExtensions DisableDelayedExpansion
for %%R in ("%~dp0..\..") do set "COZY_NATIVE_ROOT=%%~fR"
if not exist "%COZY_NATIVE_ROOT%\Cozy.Source\" exit /b 1
cd /d "%COZY_NATIVE_ROOT%"
set "COZY_SOURCE_PATHS=Cozy.Source\Cozy.Application;Cozy.Source\Cozy.Lifecycle;Cozy.Source\Cozy.Platform;Cozy.Source\Cozy.Security;Cozy.Source\Cozy.Protection;Cozy.Source\Cozy.Network;Cozy.Source\Cozy.Identity;Cozy.Source\Cozy.Integrity;Cozy.Source\Cozy.Crypto;Cozy.Source\Cozy.Overlay;Cozy.Source\Cozy.Handoff;Cozy.Source\Cozy.Configuration;Cozy.Tests\Cozy.Build;Cozy.Tests\Cozy.Configuration;Cozy.Tests\Cozy.Crypto;Cozy.Tests\Cozy.FaultInjection;Cozy.Tests\Cozy.Handoff;Cozy.Tests\Cozy.Identity;Cozy.Tests\Cozy.Integrity;Cozy.Tests\Cozy.Lifecycle;Cozy.Tests\Cozy.Network;Cozy.Tests\Cozy.Overlay;Cozy.Tests\Cozy.Platform;Cozy.Tests\Cozy.Protocol;Cozy.Tests\Cozy.Security;Cozy.Tests\Cozy.Startup"
if errorlevel 1 exit /b 1
if not defined BDS goto failed
if not exist "%BDS%\bin\bcc64.exe" goto failed
if not exist "%BDS%\bin\dcc64.exe" goto failed
call "%BDS%\bin\rsvars.bat"
if errorlevel 1 goto failed
if not "%~1"=="" if /i not "%~1"=="/build-only" goto failed
set "OVERLAY_TEST_OUT=%CD%\build\tests\overlay-contracts"
if not exist "%OVERLAY_TEST_OUT%" mkdir "%OVERLAY_TEST_OUT%"
if errorlevel 1 goto failed
call "Cozy.ImGui\Cozy.Build\Cozy.Build_ImGui_Win64.bat" "%BDS%"
if errorlevel 1 goto failed
if exist "%COZY_NATIVE_ROOT%\Cozy.BuildOutputs\Cozy.ImGui\Cozy.game_imgui_fault_test.o" del /q "%COZY_NATIVE_ROOT%\Cozy.BuildOutputs\Cozy.ImGui\Cozy.game_imgui_fault_test.o"
"%BDS%\bin\bcc64.exe" -c -std=c++11 -O2 -fno-exceptions -fno-rtti -fno-builtin -fno-use-cxa-atexit -DGAME_IMGUI_FAULT_TESTS -I"Cozy.ImGui\Cozy.Vendor\Cozy.Core" -I"Cozy.ImGui\Cozy.Vendor\Cozy.Backends" -I"Cozy.ImGui\Cozy.Bridge\Cozy.Core" -isystem "%BDS%\include" -isystem "%BDS%\include\dinkumware64" -isystem "%BDS%\include\windows\crtl" -isystem "%BDS%\include\windows\sdk" -o "%COZY_NATIVE_ROOT%\Cozy.BuildOutputs\Cozy.ImGui\Cozy.game_imgui_fault_test.o" "Cozy.ImGui\Cozy.Bridge\Cozy.Core\Cozy.game_imgui_bridge.cpp"
if errorlevel 1 goto failed
if not exist "%COZY_NATIVE_ROOT%\Cozy.BuildOutputs\Cozy.ImGui\Cozy.game_imgui_fault_test.o" goto failed
call :build Cozy.OverlayFirstFrameProbe "RELEASE;GAME_OVERLAY_CONTRACT_TESTS"
if errorlevel 1 goto failed
call :build Cozy.OverlayPrivacyProbe "RELEASE;GAME_OVERLAY_CONTRACT_TESTS"
if errorlevel 1 goto failed
call :build Cozy.OverlayGpuFaultProbe "RELEASE;GAME_IMGUI_FAULT_TESTS"
if errorlevel 1 goto failed
call :build Cozy.OverlayMitigationProbe "RELEASE;GAME_OVERLAY_CONTRACT_TESTS"
if errorlevel 1 goto failed
call :build Cozy.OverlayShutdownProbe "RELEASE;GAME_OVERLAY_CONTRACT_TESTS"
if errorlevel 1 goto failed
if /i "%~1"=="/build-only" (
  echo Overlay native probes compiled. GPU runtime checks were not executed.
  popd
  exit /b 0
)
"%OVERLAY_TEST_OUT%\Cozy.OverlayShutdownProbe.exe"
if errorlevel 1 goto failed
"%OVERLAY_TEST_OUT%\Cozy.OverlayGpuFaultProbe.exe"
if errorlevel 1 goto failed
"%OVERLAY_TEST_OUT%\Cozy.OverlayFirstFrameProbe.exe"
if errorlevel 1 goto failed
"%OVERLAY_TEST_OUT%\Cozy.OverlayPrivacyProbe.exe"
if errorlevel 1 goto failed
echo PASS actual HWND, D3D11, first-frame READY and GPU failure matrix.
exit /b 0
:build
set "COZY_PROBE_SOURCE="
if /i "%~1"=="Cozy.ApiPointerCodecProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Platform\Cozy.ApiPointerCodecProbe.dpr"
if /i "%~1"=="Cozy.ApiResolverProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Platform\Cozy.ApiResolverProbe.dpr"
if /i "%~1"=="Cozy.Blake3ParallelProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Crypto\Cozy.Blake3ParallelProbe.dpr"
if /i "%~1"=="Cozy.CompilerDefineGuardProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Platform\Cozy.CompilerDefineGuardProbe.dpr"
if /i "%~1"=="Cozy.CrcPeProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.CrcPeProbe.dpr"
if /i "%~1"=="Cozy.CrcProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.CrcProbe.dpr"
if /i "%~1"=="Cozy.DeterministicStateProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Protocol\Cozy.DeterministicStateProbe.dpr"
if /i "%~1"=="Cozy.DeviceIdentityProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Identity\Cozy.DeviceIdentityProbe.dpr"
if /i "%~1"=="Cozy.DeviceSecurityHandoffProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Handoff\Cozy.DeviceSecurityHandoffProbe.dpr"
if /i "%~1"=="Cozy.DeviceSignalsProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Identity\Cozy.DeviceSignalsProbe.dpr"
if /i "%~1"=="Cozy.FloatJsonProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Protocol\Cozy.FloatJsonProbe.dpr"
if /i "%~1"=="Cozy.HandoffCryptoProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Handoff\Cozy.HandoffCryptoProbe.dpr"
if /i "%~1"=="Cozy.HandoffKdfProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Handoff\Cozy.HandoffKdfProbe.dpr"
if /i "%~1"=="Cozy.HandoffPipeProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Handoff\Cozy.HandoffPipeProbe.dpr"
if /i "%~1"=="Cozy.HandoffProcessProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Handoff\Cozy.HandoffProcessProbe.dpr"
if /i "%~1"=="Cozy.HardeningContractsProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Security\Cozy.HardeningContractsProbe.dpr"
if /i "%~1"=="Cozy.HashContracts" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Crypto\Cozy.HashContracts.dpr"
if /i "%~1"=="Cozy.HashProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Crypto\Cozy.HashProbe.dpr"
if /i "%~1"=="Cozy.IntegrityHashProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Crypto\Cozy.IntegrityHashProbe.dpr"
if /i "%~1"=="Cozy.JsonEnvelopeProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Protocol\Cozy.JsonEnvelopeProbe.dpr"
if /i "%~1"=="Cozy.LargeModuleSizeProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.LargeModuleSizeProbe.dpr"
if /i "%~1"=="Cozy.LicenseStateProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Security\Cozy.LicenseStateProbe.dpr"
if /i "%~1"=="Cozy.LifetimeProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Lifecycle\Cozy.LifetimeProbe.dpr"
if /i "%~1"=="Cozy.MeasurementCompletionProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.MeasurementCompletionProbe.dpr"
if /i "%~1"=="Cozy.MeasurementLifetimeProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Lifecycle\Cozy.MeasurementLifetimeProbe.dpr"
if /i "%~1"=="Cozy.MetadataProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Configuration\Cozy.MetadataProbe.dpr"
if /i "%~1"=="Cozy.ModuleGenerationFixture" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.ModuleGenerationFixture.dpr"
if /i "%~1"=="Cozy.NativeAbiProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Platform\Cozy.NativeAbiProbe.dpr"
if /i "%~1"=="Cozy.NativeApiContractsProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Platform\Cozy.NativeApiContractsProbe.dpr"
if /i "%~1"=="Cozy.OverlayEnvironmentProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Overlay\Cozy.OverlayEnvironmentProbe.dpr"
if /i "%~1"=="Cozy.OverlayFirstFrameProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Overlay\Cozy.OverlayFirstFrameProbe.dpr"
if /i "%~1"=="Cozy.OverlayGpuFaultProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Overlay\Cozy.OverlayGpuFaultProbe.dpr"
if /i "%~1"=="Cozy.OverlayMitigationProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Overlay\Cozy.OverlayMitigationProbe.dpr"
if /i "%~1"=="Cozy.OverlayPrivacyProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Overlay\Cozy.OverlayPrivacyProbe.dpr"
if /i "%~1"=="Cozy.OverlayRenewalScheduleProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Overlay\Cozy.OverlayRenewalScheduleProbe.dpr"
if /i "%~1"=="Cozy.OverlayShutdownProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Overlay\Cozy.OverlayShutdownProbe.dpr"
if /i "%~1"=="Cozy.PeCorpusProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.PeCorpusProbe.dpr"
if /i "%~1"=="Cozy.ProcessMitigationProfileProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Security\Cozy.ProcessMitigationProfileProbe.dpr"
if /i "%~1"=="Cozy.ProtocolSchemaProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Protocol\Cozy.ProtocolSchemaProbe.dpr"
if /i "%~1"=="Cozy.SelfIntegrityProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.SelfIntegrityProbe.dpr"
if /i "%~1"=="Cozy.ServerPolicyLocalProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Security\Cozy.ServerPolicyLocalProbe.dpr"
if /i "%~1"=="Cozy.StartupProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Startup\Cozy.StartupProbe.dpr"
if /i "%~1"=="Cozy.ThreadInventoryProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Lifecycle\Cozy.ThreadInventoryProbe.dpr"
if /i "%~1"=="Cozy.TlsContractProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.TlsContractProbe.dpr"
if /i "%~1"=="Cozy.TlsPinWindowProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.TlsPinWindowProbe.dpr"
if /i "%~1"=="Cozy.TlsReceiveProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.TlsReceiveProbe.dpr"
if /i "%~1"=="Cozy.DeviceKeyContractProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Identity\Cozy.DeviceKeyContractProbe.dpr"
if /i "%~1"=="Cozy.RecoveryDeviceProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Identity\Cozy.RecoveryDeviceProbe.dpr"
if /i "%~1"=="Cozy.ClientFaultTest" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.FaultInjection\Cozy.ClientFaultTest.dpr"
if /i "%~1"=="Cozy.LauncherFaultTest" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.FaultInjection\Cozy.LauncherFaultTest.dpr"
if /i "%~1"=="Cozy.OverlayFaultTest" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.FaultInjection\Cozy.OverlayFaultTest.dpr"
if not defined COZY_PROBE_SOURCE exit /b 1
set "OVERLAY_TEST_EXPECTED=%OVERLAY_TEST_OUT%\%~1.exe"
if exist "%OVERLAY_TEST_EXPECTED%\" (
  echo ERROR: PROBE_OUTPUT_IS_DIRECTORY: "%OVERLAY_TEST_EXPECTED%"
  exit /b 1
)
if exist "%OVERLAY_TEST_EXPECTED%" del /f /q "%OVERLAY_TEST_EXPECTED%"
if exist "%OVERLAY_TEST_EXPECTED%" (
  echo ERROR: PROBE_STALE_OUTPUT_LOCKED: "%OVERLAY_TEST_EXPECTED%"
  echo Close the previous probe process before rebuilding. No stale output will run.
  exit /b 1
)
set "OVERLAY_TEST_UNITS=%OVERLAY_TEST_OUT%\units\%~1"
if exist "%OVERLAY_TEST_UNITS%" rmdir /s /q "%OVERLAY_TEST_UNITS%"
if errorlevel 1 exit /b 1
mkdir "%OVERLAY_TEST_UNITS%"
if errorlevel 1 exit /b 1
"%BDS%\bin\dcc64.exe" -B -Q -D"%~2" -U"%COZY_SOURCE_PATHS%" -I"%COZY_SOURCE_PATHS%" -O"Cozy.BuildOutputs\Cozy.ImGui" -E"%OVERLAY_TEST_OUT%" -N0"%OVERLAY_TEST_UNITS%" "%COZY_PROBE_SOURCE%"
set "OVERLAY_TEST_BUILD_EXIT=%ERRORLEVEL%"
if not "%OVERLAY_TEST_BUILD_EXIT%"=="0" (
  if exist "%OVERLAY_TEST_EXPECTED%" if not exist "%OVERLAY_TEST_EXPECTED%\" del /f /q "%OVERLAY_TEST_EXPECTED%"
  echo ERROR: PROBE_COMPILER_FAILED: %~1 - exit %OVERLAY_TEST_BUILD_EXIT%.
  exit /b 1
)
if not exist "%OVERLAY_TEST_EXPECTED%" (
  echo ERROR: PROBE_NO_FRESH_OUTPUT: dcc64 returned success but created no new output.
  echo Expected: "%OVERLAY_TEST_EXPECTED%"
  echo A trial or edition may forbid command-line compilation even with exit code 0.
  echo Use the supported license or Cozy.ManualNativeTests.groupproj in the RAD Studio IDE.
  exit /b 1
)
if exist "%OVERLAY_TEST_EXPECTED%\" (
  echo ERROR: PROBE_OUTPUT_IS_DIRECTORY: "%OVERLAY_TEST_EXPECTED%"
  exit /b 1
)
for %%F in ("%OVERLAY_TEST_EXPECTED%") do if %%~zF LSS 512 (
  del /f /q "%OVERLAY_TEST_EXPECTED%"
  echo ERROR: PROBE_OUTPUT_INVALID: %~1 produced an empty or truncated file.
  exit /b 1
)
exit /b 0
:failed
echo ERROR: Overlay native contract build/run failed. No runtime PASS was recorded.
exit /b 1
