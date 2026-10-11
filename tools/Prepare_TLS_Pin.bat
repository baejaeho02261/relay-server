@echo off
setlocal
cd /d "%~dp0"
node "%~dp0tls-pin-maintenance.js" prepare
exit /b %errorlevel%
