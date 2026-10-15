@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PRODUCT_FAULT_NOPAUSE="
set "PRODUCT_FAULT_INPUT=%~1"
if /i "%~1"=="/nopause" (set "PRODUCT_FAULT_NOPAUSE=1" & set "PRODUCT_FAULT_INPUT=")
if /i "%~2"=="/nopause" set "PRODUCT_FAULT_NOPAUSE=1"
where pwsh.exe >nul 2>nul
if errorlevel 1 (
  echo ERROR: PowerShell 7 x64 is required. Build dedicated test projects in RAD Studio IDE first.
  set "PRODUCT_FAULT_EXIT=1"
  goto done
)
pwsh.exe -NoLogo -NoProfile -File "%~dp0product-fault-tests.ps1" -InputFile "%PRODUCT_FAULT_INPUT%"
set "PRODUCT_FAULT_EXIT=%ERRORLEVEL%"
:done
if not defined PRODUCT_FAULT_NOPAUSE pause
exit /b %PRODUCT_FAULT_EXIT%
