@echo off
setlocal EnableExtensions DisableDelayedExpansion
title cozy.Client - Optional source/server checks
where node.exe >nul 2>&1
if errorlevel 1 goto :no_node
if not exist "%~dp0peace.release-openssl-bootstrap.js" goto :wrong_folder
if not exist "%~dp0..\artifacts\peace.release-preflight.js" goto :wrong_folder
cd /d "%~dp0..\.."
if errorlevel 1 goto :wrong_folder
set "NODE_OPTIONS="
set "NODE_PATH="
echo ============================================================
echo  cozy.Client - Optional source/server checks. No report is required for publication.
echo ============================================================
echo Existing reports are preserved. No software is installed.
echo Real Windows A/B/O products are NOT executed.
echo.
node.exe "%~dp0peace.release-openssl-bootstrap.js" --preflight-auto
set "RESULT=%ERRORLEVEL%"
echo.
if "%RESULT%"=="0" (echo [OK] Preflight completed. This is NOT publication approval.) else (echo [FAIL] Keep the result directory and logs shown above.)
pause
endlocal & exit /b %RESULT%
:no_node
echo [ERROR] node.exe was not found.
goto :failed
:wrong_folder
echo [ERROR] Extract this patch into the existing project first.
:failed
pause
endlocal & exit /b 1
