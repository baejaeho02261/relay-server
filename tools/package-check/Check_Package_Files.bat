@echo off
setlocal EnableExtensions DisableDelayedExpansion
pushd "%~dp0" >nul 2>&1
if errorlevel 1 exit /b 2
where node.exe >nul 2>&1
if errorlevel 1 goto :node_error
node "%~dp0verify-package.js" --root "%~dp0..\.."
set "CHECK_RC=%ERRORLEVEL%"
popd
exit /b %CHECK_RC%
:node_error
echo [ERROR] Node.js 24.22.1 was not found. No files were changed.
popd
exit /b 2
