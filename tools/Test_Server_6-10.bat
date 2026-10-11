@echo off
setlocal
cd /d "%~dp0"
node "%~dp0..\scripts\run-server-contracts-6-10.js" "%CD%"
exit /b %errorlevel%
