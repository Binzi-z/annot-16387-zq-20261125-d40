@echo off
setlocal
cd /d "%~dp0"
python run_checks.py
if errorlevel 1 exit /b 1
endlocal
