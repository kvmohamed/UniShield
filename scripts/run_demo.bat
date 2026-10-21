@echo off
:: ================================================================
:: UniShield - one-command offline demo (Windows)
::
::   scripts\run_demo.bat            full demo (several minutes)
::   scripts\run_demo.bat --quick    shorter demo (about a minute)
::   scripts\run_demo.bat --serve    then start the dashboard
::
:: All data is synthetic or written locally. Nothing is sent on any network.
:: ================================================================
setlocal
cd /d "%~dp0.."

set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"

"%PY%" scripts\run_demo.py %*
set "RC=%ERRORLEVEL%"
endlocal & exit /b %RC%
