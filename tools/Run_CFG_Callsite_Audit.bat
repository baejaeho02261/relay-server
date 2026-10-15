@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "GAME_CFG_EXIT=1"
set "NODE_OPTIONS="
set "NODE_REPL_EXTERNAL_MODULE="
"%SystemRoot%\System32\where.exe" node.exe >nul 2>&1
if errorlevel 1 goto missing_node
node.exe "%~dp0cfg-callsite-console.js" %*
set "GAME_CFG_EXIT=%ERRORLEVEL%"
goto finish
:missing_node
echo ERROR: node.exe was not found in PATH.
:finish
if "%~1"=="" pause
endlocal & exit /b %GAME_CFG_EXIT%
