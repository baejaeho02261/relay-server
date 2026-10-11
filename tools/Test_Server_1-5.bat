@echo off
setlocal
cd /d "%~dp0"
node "%~dp0..\scripts\run-server-contracts-1-5.js" "%CD%"
exit /b %errorlevel%
