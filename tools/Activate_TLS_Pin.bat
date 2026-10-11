@echo off
setlocal
cd /d "%~dp0"
node "%~dp0tls-pin-maintenance.js" activate
exit /b %errorlevel%
