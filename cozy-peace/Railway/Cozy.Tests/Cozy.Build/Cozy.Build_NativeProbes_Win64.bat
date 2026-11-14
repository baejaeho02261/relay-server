@echo off
setlocal EnableExtensions DisableDelayedExpansion
for %%R in ("%~dp0..\..") do set "COZY_NATIVE_ROOT=%%~fR"
if not exist "%COZY_NATIVE_ROOT%\Cozy.Source\" exit /b 1
cd /d "%COZY_NATIVE_ROOT%"
set "COZY_SOURCE_PATHS=Cozy.Source\Cozy.Application;Cozy.Source\Cozy.Lifecycle;Cozy.Source\Cozy.Platform;Cozy.Source\Cozy.Security;Cozy.Source\Cozy.Protection;Cozy.Source\Cozy.Network;Cozy.Source\Cozy.Identity;Cozy.Source\Cozy.Integrity;Cozy.Source\Cozy.Crypto;Cozy.Source\Cozy.Overlay;Cozy.Source\Cozy.Handoff;Cozy.Source\Cozy.Configuration;Cozy.Tests\Cozy.Build;Cozy.Tests\Cozy.Configuration;Cozy.Tests\Cozy.Crypto;Cozy.Tests\Cozy.FaultInjection;Cozy.Tests\Cozy.Handoff;Cozy.Tests\Cozy.Identity;Cozy.Tests\Cozy.Integrity;Cozy.Tests\Cozy.Lifecycle;Cozy.Tests\Cozy.Network;Cozy.Tests\Cozy.Overlay;Cozy.Tests\Cozy.Platform;Cozy.Tests\Cozy.Protocol;Cozy.Tests\Cozy.Security;Cozy.Tests\Cozy.Startup"
if not defined BDS (
  echo Run this script from the RAD Studio 13.1 Command Prompt.
  exit /b 1
)
if not exist "%BDS%\bin\dcc64.exe" (
  echo dcc64.exe was not found under BDS.
  exit /b 1
)
call "%BDS%\bin\rsvars.bat"
if errorlevel 1 exit /b 1
call "Cozy.ImGui\Cozy.Build\Cozy.Build_ImGui_Win64.bat" "%BDS%"
if errorlevel 1 exit /b 1
if not "%~1"=="" if /i not "%~1"=="/build-only" (
  echo Usage: Cozy.Build_NativeProbes_Win64.bat [/build-only]
  exit /b 1
)
set "PROBE_OUT=%CD%\build\tests\native-probes"
if not exist "%PROBE_OUT%" mkdir "%PROBE_OUT%"
if errorlevel 1 exit /b 1
for %%P in (Cozy.ModuleGenerationFixture Cozy.ApiPointerCodecProbe Cozy.ApiResolverProbe Cozy.ServerPolicyLocalProbe Cozy.MetadataProbe Cozy.SelfIntegrityProbe Cozy.ProtocolSchemaProbe Cozy.HashProbe Cozy.HashContracts Cozy.IntegrityHashProbe Cozy.LicenseStateProbe Cozy.TlsContractProbe Cozy.TransportProbe Cozy.CrcProbe Cozy.DeviceSecurityHandoffProbe Cozy.DeviceSecurityOwnedProbe Cozy.LauncherStartupProbe Cozy.ClientStartupProbe Cozy.OverlayStartupProbe Cozy.StartupProbe Cozy.HandoffCryptoProbe Cozy.HandoffPipeProbe Cozy.HandoffProcessProbe Cozy.NativeAbiProbe Cozy.LifetimeProbe Cozy.HardeningContractsProbe Cozy.PeCorpusProbe Cozy.CrcPeProbe Cozy.DeterministicStateProbe Cozy.TlsPinWindowProbe Cozy.ProcessMitigationProfileProbe Cozy.NativeApiContractsProbe Cozy.MeasurementLifetimeProbe Cozy.MeasurementCompletionProbe Cozy.JsonEnvelopeProbe Cozy.ThreadInventoryProbe Cozy.Blake3ParallelProbe Cozy.KeylessApprovalProbe Cozy.LicenseOwnershipProbe Cozy.HashLifecycleProbe Cozy.HandoffKdfProbe Cozy.DeviceSignalsProbe Cozy.ServerOperationsProtocolProbe Cozy.PointerGraphProbe Cozy.ServerProfileProbe Cozy.OwnedRuntimeProbe Cozy.LifecycleContractsProbe Cozy.DeviceIdentityProbe) do (
  call :build %%P
  if errorlevel 1 exit /b 1
)
if /i "%~1"=="/build-only" (
  echo Native probes compiled. Runtime checks were skipped by request.
  exit /b 0
)
for %%P in (Cozy.ApiPointerCodecProbe Cozy.ApiResolverProbe Cozy.ServerPolicyLocalProbe Cozy.MetadataProbe Cozy.SelfIntegrityProbe Cozy.ProtocolSchemaProbe Cozy.HashContracts Cozy.IntegrityHashProbe Cozy.LicenseStateProbe Cozy.TlsContractProbe Cozy.TransportProbe Cozy.CrcProbe Cozy.DeviceSecurityHandoffProbe Cozy.DeviceSecurityOwnedProbe Cozy.LauncherStartupProbe Cozy.ClientStartupProbe Cozy.OverlayStartupProbe Cozy.StartupProbe Cozy.HandoffCryptoProbe Cozy.HandoffPipeProbe Cozy.HandoffProcessProbe Cozy.NativeAbiProbe Cozy.LifetimeProbe Cozy.HardeningContractsProbe Cozy.DeterministicStateProbe Cozy.TlsPinWindowProbe Cozy.ProcessMitigationProfileProbe Cozy.NativeApiContractsProbe Cozy.MeasurementLifetimeProbe Cozy.MeasurementCompletionProbe Cozy.JsonEnvelopeProbe Cozy.ThreadInventoryProbe Cozy.Blake3ParallelProbe Cozy.KeylessApprovalProbe Cozy.LicenseOwnershipProbe Cozy.HashLifecycleProbe Cozy.HandoffKdfProbe Cozy.DeviceSignalsProbe Cozy.ServerOperationsProtocolProbe Cozy.PointerGraphProbe Cozy.ServerProfileProbe Cozy.OwnedRuntimeProbe Cozy.LifecycleContractsProbe) do (
  echo Running %%P...
  "%PROBE_OUT%\%%P.exe"
  if errorlevel 1 exit /b 1
)
"%PROBE_OUT%\Cozy.DeviceIdentityProbe.exe" --contracts
if errorlevel 1 exit /b 1
"%PROBE_OUT%\Cozy.MeasurementLifetimeProbe.exe" --loader-fixture "%PROBE_OUT%\Cozy.ModuleGenerationFixture.dll"
if errorlevel 1 exit /b 1
"%PROBE_OUT%\Cozy.ProcessMitigationProfileProbe.exe" --prohibit
if errorlevel 1 exit /b 1
echo Running opt-in mitigation check in its own probe process...
"%PROBE_OUT%\Cozy.ServerPolicyLocalProbe.exe" --prohibit
if errorlevel 1 exit /b 1
for %%M in (hash keyed derive) do (
  echo Running Cozy.HashProbe %%M streaming checks...
  "%PROBE_OUT%\Cozy.HashProbe.exe" "Cozy.Source\Cozy.Configuration\Cozy.Metadata.inc" 127 %%M 131
  if errorlevel 1 exit /b 1
)
node "..\Relay Server\tests\artifacts\peace.test-hardening-pe-corpus.js" --native "%PROBE_OUT%\Cozy.PeCorpusProbe.exe"
if errorlevel 1 exit /b 1
node "..\Relay Server\tests\protocol\peace.test-independent-contracts-14.js" --native "%PROBE_OUT%\Cozy.DeterministicStateProbe.exe" --native-pe "%PROBE_OUT%\Cozy.PeCorpusProbe.exe" --native-crc "%PROBE_OUT%\Cozy.CrcProbe.exe"
if errorlevel 1 exit /b 1
node "..\Relay Server\tests\artifacts\peace.compare-native-crc-pe.js" --probe "%PROBE_OUT%\Cozy.CrcPeProbe.exe"
if errorlevel 1 exit /b 1
echo PASS: all compiled native probes completed successfully.
echo These local probes do not authorize a server session or validate the Overlay GUI.
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
if /i "%~1"=="Cozy.DeviceSecurityOwnedProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Security\Cozy.DeviceSecurityOwnedProbe.dpr"
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
if /i "%~1"=="Cozy.ServerOperationsProtocolProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Security\Cozy.ServerOperationsProtocolProbe.dpr"
if /i "%~1"=="Cozy.PointerGraphProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Platform\Cozy.PointerGraphProbe.dpr"
if /i "%~1"=="Cozy.StartupProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Startup\Cozy.StartupProbe.dpr"
if /i "%~1"=="Cozy.OverlayStartupProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Startup\Cozy.OverlayStartupProbe.dpr"
if /i "%~1"=="Cozy.ClientStartupProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Startup\Cozy.ClientStartupProbe.dpr"
if /i "%~1"=="Cozy.LauncherStartupProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Startup\Cozy.LauncherStartupProbe.dpr"
if /i "%~1"=="Cozy.ThreadInventoryProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Lifecycle\Cozy.ThreadInventoryProbe.dpr"
if /i "%~1"=="Cozy.TlsContractProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.TlsContractProbe.dpr"
if /i "%~1"=="Cozy.TransportProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.TransportProbe.dpr"
if /i "%~1"=="Cozy.TlsPinWindowProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.TlsPinWindowProbe.dpr"
if /i "%~1"=="Cozy.TlsReceiveProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.TlsReceiveProbe.dpr"
if /i "%~1"=="Cozy.DeviceKeyContractProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Identity\Cozy.DeviceKeyContractProbe.dpr"
if /i "%~1"=="Cozy.RecoveryDeviceProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Identity\Cozy.RecoveryDeviceProbe.dpr"
if /i "%~1"=="Cozy.ClientFaultTest" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.FaultInjection\Cozy.ClientFaultTest.dpr"
if /i "%~1"=="Cozy.LauncherFaultTest" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.FaultInjection\Cozy.LauncherFaultTest.dpr"
if /i "%~1"=="Cozy.OverlayFaultTest" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.FaultInjection\Cozy.OverlayFaultTest.dpr"
if /i "%~1"=="Cozy.HashLifecycleProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Crypto\Cozy.HashLifecycleProbe.dpr"
if /i "%~1"=="Cozy.LicenseOwnershipProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.FaultInjection\Cozy.LicenseOwnershipProbe.dpr"
if /i "%~1"=="Cozy.KeylessApprovalProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Identity\Cozy.KeylessApprovalProbe.dpr"
if /i "%~1"=="Cozy.ServerProfileProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Network\Cozy.ServerProfileProbe.dpr"
if /i "%~1"=="Cozy.OwnedRuntimeProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Integrity\Cozy.OwnedRuntimeProbe.dpr"
if /i "%~1"=="Cozy.LifecycleContractsProbe" set "COZY_PROBE_SOURCE=Cozy.Tests\Cozy.Lifecycle\Cozy.LifecycleContractsProbe.dpr"
if not defined COZY_PROBE_SOURCE exit /b 1
set "PROBE_EXPECTED=%PROBE_OUT%\%~1.exe"
if /i "%~1"=="Cozy.ModuleGenerationFixture" set "PROBE_EXPECTED=%PROBE_OUT%\%~1.dll"
if exist "%PROBE_EXPECTED%\" (
  echo ERROR: PROBE_OUTPUT_IS_DIRECTORY: "%PROBE_EXPECTED%"
  exit /b 1
)
if exist "%PROBE_EXPECTED%" del /f /q "%PROBE_EXPECTED%"
if exist "%PROBE_EXPECTED%" (
  echo ERROR: PROBE_STALE_OUTPUT_LOCKED: "%PROBE_EXPECTED%"
  echo Close the previous probe process before rebuilding. No stale output will run.
  exit /b 1
)
echo Compiling %~1 with dcc64 Release Win64...
set "PROBE_DEFINES=RELEASE"
if /i "%~1"=="Cozy.OverlayStartupProbe" set "PROBE_DEFINES=RELEASE;GAME_STARTUP_ROLE_PROBE"
if /i "%~1"=="Cozy.ClientStartupProbe" set "PROBE_DEFINES=RELEASE;GAME_STARTUP_ROLE_PROBE"
if /i "%~1"=="Cozy.LauncherStartupProbe" set "PROBE_DEFINES=RELEASE;GAME_STARTUP_ROLE_PROBE"
set "PROBE_UNITS=%PROBE_OUT%\units\%~1"
if exist "%PROBE_UNITS%" rmdir /s /q "%PROBE_UNITS%"
if errorlevel 1 exit /b 1
mkdir "%PROBE_UNITS%"
if errorlevel 1 exit /b 1
if /i "%~1"=="Cozy.TlsContractProbe" set "PROBE_DEFINES=RELEASE;GAME_TLS_CONTRACT_TESTS"
if /i "%~1"=="Cozy.TlsReceiveProbe" set "PROBE_DEFINES=RELEASE;GAME_TLS_CONTRACT_TESTS"
if /i "%~1"=="Cozy.TransportProbe" set "PROBE_DEFINES=RELEASE;GAME_TRANSPORT_TESTS"
if /i "%~1"=="Cozy.DeviceSecurityOwnedProbe" set "PROBE_DEFINES=RELEASE;GAME_DEVICE_SECURITY_TESTS"
if /i "%~1"=="Cozy.LicenseStateProbe" set "PROBE_DEFINES=RELEASE;GAME_LICENSE_CONTRACT_TESTS"
if /i "%~1"=="Cozy.HandoffProcessProbe" set "PROBE_DEFINES=RELEASE;GAME_HANDOFF_CONTRACT_TESTS"
if /i "%~1"=="Cozy.HandoffPipeProbe" set "PROBE_DEFINES=RELEASE;GAME_HANDOFF_CONTRACT_TESTS"
if /i "%~1"=="Cozy.MeasurementLifetimeProbe" set "PROBE_DEFINES=RELEASE;GAME_MEASUREMENT_TESTS"
if /i "%~1"=="Cozy.NativeAbiProbe" set "PROBE_DEFINES=RELEASE;GAME_NATIVE_ABI_TESTS"
if /i "%~1"=="Cozy.CrcPeProbe" set "PROBE_DEFINES=RELEASE;GAME_CRC_PE_PROBE"
if /i "%~1"=="Cozy.PointerGraphProbe" set "PROBE_DEFINES=RELEASE;COZY_POINTER_GRAPH_PROBE"
if /i "%~1"=="Cozy.HashLifecycleProbe" set "PROBE_DEFINES=RELEASE;COZY_HASH_WORKER_TESTS"
if /i "%~1"=="Cozy.DeviceIdentityProbe" set "PROBE_DEFINES=RELEASE;GAME_DEVICE_IDENTITY_PROBE"
if /i "%~1"=="Cozy.MeasurementCompletionProbe" set "PROBE_DEFINES=RELEASE;GAME_OWN_MEASUREMENT_TESTS"
if /i "%~1"=="Cozy.LifecycleContractsProbe" set "PROBE_DEFINES=RELEASE;GAME_LIFECYCLE_CONTRACT_TESTS"
"%BDS%\bin\dcc64.exe" -B -Q -D"%PROBE_DEFINES%" -U"%COZY_SOURCE_PATHS%" -I"%COZY_SOURCE_PATHS%" -O"Cozy.BuildOutputs\Cozy.ImGui" -E"%PROBE_OUT%" -N0"%PROBE_UNITS%" "%COZY_PROBE_SOURCE%"
set "PROBE_BUILD_EXIT=%ERRORLEVEL%"
if not "%PROBE_BUILD_EXIT%"=="0" (
  if exist "%PROBE_EXPECTED%" if not exist "%PROBE_EXPECTED%\" del /f /q "%PROBE_EXPECTED%"
  echo ERROR: PROBE_COMPILER_FAILED: %~1 - exit %PROBE_BUILD_EXIT%.
  exit /b 1
)
if not exist "%PROBE_EXPECTED%" (
  echo ERROR: PROBE_NO_FRESH_OUTPUT: dcc64 returned success but created no new output.
  echo Expected: "%PROBE_EXPECTED%"
  echo A trial or edition may forbid command-line compilation even with exit code 0.
  echo Use the supported license or Cozy.ManualNativeTests.groupproj in the RAD Studio IDE.
  exit /b 1
)
if exist "%PROBE_EXPECTED%\" (
  echo ERROR: PROBE_OUTPUT_IS_DIRECTORY: "%PROBE_EXPECTED%"
  exit /b 1
)
for %%F in ("%PROBE_EXPECTED%") do if %%~zF LSS 512 (
  del /f /q "%PROBE_EXPECTED%"
  echo ERROR: PROBE_OUTPUT_INVALID: %~1 produced an empty or truncated file.
  exit /b 1
)
exit /b 0
