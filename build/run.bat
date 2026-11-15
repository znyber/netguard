@echo off
cd /d "%~dp0"

:: Start NetGuard in a separate CMD window
start "NetGuard Server" cmd /k "cd /d "%~dp0" && netguardc.exe"

:: Wait for NetGuard to initialize
timeout /t 3 /nobreak >nul

:: Open default browser
start "" "http://127.0.0.1:8080/"

:: Exit this script
exit