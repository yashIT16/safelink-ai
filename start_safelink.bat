@echo off
title SafeLink AI - Universal Launcher
echo ==============================================
echo SafeLink AI - Local Server Launcher
echo ==============================================

:: Navigate to project root (in case script is run as admin from System32)
cd /d "%~dp0"

echo [1/2] Starting Python Flask ML API...
echo ----------------------------------------------
cd ml-model-python
start cmd /k "title SafeLink AI (Python) && python app.py"
cd ..

:: Wait 3 seconds for Python to initialize
timeout /t 3 /nobreak > nul

echo [2/2] Starting Node.js Backend...
echo ----------------------------------------------
cd backend-node
start cmd /k "title SafeLink AI (Node.js) && npm start"
cd ..

echo.
echo ==============================================
echo SUCCESS! SafeLink AI is fully running.
echo - The Machine Learning Engine is on Port 5000
echo - The Express Backend API is on Port 3001
echo.
echo Keep the new terminal windows open.
echo You can now use the Chrome Extension!
echo ==============================================
pause
