@echo off
title SafeLink AI - Install AutoStart
echo =======================================================
echo        SafeLink AI Background Autostart Installer
echo =======================================================
echo.
echo This will configure SafeLink AI to start automatically
echo in the background whenever you turn on your computer.
echo.
echo Copying script to Windows Startup folder...
copy /Y "D:\scaning tool\safelink-ai\safelink_startup.vbs" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\safelink_startup.vbs" >nul

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] AutoStart Installed!
    echo.
    echo Would you like to start the servers in the background right now?
    echo Press any key to start them, or close this window to cancel.
    pause >nul
    wscript.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\safelink_startup.vbs"
    echo Servers started! You can now use the Chrome Extension anytime.
) else (
    echo.
    echo [ERROR] Failed to install. Please run as Administrator.
)

echo.
pause
