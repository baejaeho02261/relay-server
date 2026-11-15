@echo off
setlocal EnableExtensions DisableDelayedExpansion
where node.exe >nul 2>nul
if errorlevel 1 goto missing_node
node "%~dp0peace.run-crc-pe-comparison.js" %*
set "CRC_PE_EXIT=%ERRORLEVEL%"
exit /b %CRC_PE_EXIT%
:missing_node
echo ERROR: Node.js is required to run the CRC comparison. Install it and reopen this BAT.
set "CRC_PE_NO_PAUSE="
:scan_pause
if "%~1"=="" goto node_failed
if /i "%~1"=="/nopause" set "CRC_PE_NO_PAUSE=1"
if /i "%~1"=="--nopause" set "CRC_PE_NO_PAUSE=1"
shift
goto scan_pause
:node_failed
if not defined CRC_PE_NO_PAUSE pause
exit /b 1
