@echo off
setlocal
cd /d "%~dp0"

echo Installing the local build packages...
python -m pip install pyinstaller "python-socketio[client]" psutil
if errorlevel 1 goto error

echo.
echo Building PARAKH-Agent.exe...
python -m PyInstaller --clean --noconfirm --onefile --name PARAKH-Agent parakh_agent.py
if errorlevel 1 goto error

if exist "PARAKH-Agent-release" rmdir /s /q "PARAKH-Agent-release"
mkdir "PARAKH-Agent-release"
copy /y "dist\PARAKH-Agent.exe" "PARAKH-Agent-release\PARAKH-Agent.exe" >nul
copy /y "PARAKH-Agent-MANUAL.txt" "PARAKH-Agent-release\PARAKH-Agent-MANUAL.txt" >nul

if exist "PARAKH-Agent.zip" del /q "PARAKH-Agent.zip"
powershell -NoProfile -Command "Compress-Archive -Path 'PARAKH-Agent-release\*' -DestinationPath 'PARAKH-Agent.zip' -Force"
if errorlevel 1 goto error

echo.
echo DONE.
echo Created: %CD%\PARAKH-Agent.zip
echo.
echo Upload PARAKH-Agent.zip to your GitHub Release.
echo The first time a user runs PARAKH-Agent.exe, it installs a copy in LocalAppData and adds itself to Windows startup.
pause
exit /b 0

:error
echo.
echo Build failed. Read the error shown above.
pause
exit /b 1
