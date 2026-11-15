@echo off
rem Builds the installer. Run from the project folder AFTER building netguard.exe and netguardc.exe into .\build
rem   build-installer.bat C:\WinDivert-2.2.2-A
set WD=%1
if "%WD%"=="" set WD=C:\WinDivert-2.2.2-A
set ISCC="%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist %ISCC% set ISCC="%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (echo Inno Setup 6 not found - install it from https://jrsoftware.org/isinfo.php & exit /b 1)
%ISCC% installer\netguard.iss /DWinDivertDir=%WD%\x64
echo.
echo Installer: installer\Output\NetGuard-Setup-1.1.0.exe
