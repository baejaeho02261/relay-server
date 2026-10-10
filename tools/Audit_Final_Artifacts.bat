@echo off
setlocal
if "%~3"=="" (
  echo Usage: Audit_Final_Artifacts.bat A.exe B.exe O.exe
  exit /b 1
)
rem New JSON is colocated with this BAT; no keys, approvals or binaries change.
rem Existing output is not overwritten: archive/remove it explicitly before rerun.
node "%~dp0audit-final-artifacts.js" "%~f1" "%~f2" "%~f3" "%~dp0final-artifact-audit.json"
exit /b %errorlevel%
