@echo off
setlocal EnableExtensions DisableDelayedExpansion
if "%~1"=="" (
  echo Usage: Run_Native_Json_Differential.bat "absolute\Cozy.ProtocolJsonDifferentialProbe.exe" "new-report.json" [seed] [mutations]
  exit /b 2
)
if "%~2"=="" exit /b 2
if not "%~5"=="" exit /b 2
if "%~3"=="" goto defaults
if "%~4"=="" goto seedonly
node "%~dp0..\security\peace.native-json-differential.js" "%~1" "%~2" "%~3" "%~4"
exit /b %ERRORLEVEL%
:seedonly
node "%~dp0..\security\peace.native-json-differential.js" "%~1" "%~2" "%~3"
exit /b %ERRORLEVEL%
:defaults
node "%~dp0..\security\peace.native-json-differential.js" "%~1" "%~2"
exit /b %ERRORLEVEL%
