@echo off
title VIGIL
color 0A

set "ROOT=%~dp0"
cd /d "%ROOT%"

echo Starting VIGIL Backend...
start "VIGIL Backend" /D "%ROOT%" cmd /k "if exist .venv\Scripts\python.exe ( .venv\Scripts\python.exe api.py ) else ( python api.py )"

timeout /t 3 /nobreak >nul

echo Starting VIGIL Frontend...
start "VIGIL Frontend" /D "%ROOT%frontend" cmd /k "npm run dev"

timeout /t 5 /nobreak >nul

start http://localhost:5173

exit

