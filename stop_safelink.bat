@echo off
title SafeLink AI - Stop Servers
echo =======================================================
echo        SafeLink AI Background Shutdown Tool
echo =======================================================
echo.
echo Stopping Python API (Port 5001)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5001" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo Stopping Node Server (Port 3001)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3001" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo Servers successfully stopped.
pause
