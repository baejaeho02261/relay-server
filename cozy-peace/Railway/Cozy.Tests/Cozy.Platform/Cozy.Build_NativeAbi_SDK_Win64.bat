@echo off
setlocal EnableExtensions DisableDelayedExpansion
for %%R in ("%~dp0..\..") do set "COZY_NATIVE_ROOT=%%~fR"
if not exist "%COZY_NATIVE_ROOT%\Cozy.Source\" exit /b 1
cd /d "%COZY_NATIVE_ROOT%"
set "COZY_SOURCE_PATHS=Cozy.Source\Cozy.Application;Cozy.Source\Cozy.Lifecycle;Cozy.Source\Cozy.Platform;Cozy.Source\Cozy.Security;Cozy.Source\Cozy.Protection;Cozy.Source\Cozy.Network;Cozy.Source\Cozy.Identity;Cozy.Source\Cozy.Integrity;Cozy.Source\Cozy.Crypto;Cozy.Source\Cozy.Overlay;Cozy.Source\Cozy.Handoff;Cozy.Source\Cozy.Configuration;Cozy.Tests\Cozy.Build;Cozy.Tests\Cozy.Configuration;Cozy.Tests\Cozy.Crypto;Cozy.Tests\Cozy.FaultInjection;Cozy.Tests\Cozy.Handoff;Cozy.Tests\Cozy.Identity;Cozy.Tests\Cozy.Integrity;Cozy.Tests\Cozy.Lifecycle;Cozy.Tests\Cozy.Network;Cozy.Tests\Cozy.Overlay;Cozy.Tests\Cozy.Platform;Cozy.Tests\Cozy.Protocol;Cozy.Tests\Cozy.Security;Cozy.Tests\Cozy.Startup"
where cl.exe >nul 2>&1
if errorlevel 1 (
  echo Run from an x64 Native Tools Command Prompt for Visual Studio with Windows SDK installed.
  echo This independent SDK verifier is optional for product compilation, required for the ABI comparison gate.
  exit /b 1
)
set "ABI_OUT=%CD%\build\tests\native-sdk"
if not exist "%ABI_OUT%" mkdir "%ABI_OUT%"
if errorlevel 1 exit /b 1
cl.exe /nologo /W4 /WX /EHsc /DWIN32_LEAN_AND_MEAN /Fo"%ABI_OUT%\Cozy.NativeAbiSdkProbe.obj" /Fe"%ABI_OUT%\Cozy.NativeAbiSdkProbe.exe" "Cozy.Tests\Cozy.Platform\Cozy.NativeAbiSdkProbe.cpp"
if errorlevel 1 exit /b 1
echo SDK ABI probe built: "%ABI_OUT%\Cozy.NativeAbiSdkProbe.exe"
echo Compare it with the Delphi probe using Cozy.Tests\Cozy.Platform\Cozy.Compare-NativeAbi.ps1.
exit /b 0
