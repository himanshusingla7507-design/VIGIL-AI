@echo off
title VIGIL
color 0A

cd /d C:\Users\himan\OneDrive\Desktop\VIGIL-main

echo Starting VIGIL Backend...
start "VIGIL Backend" cmd /k "call .venv\Scripts\activate.bat && python api.py"

timeout /t 3 /nobreak >nul

echo Starting VIGIL Frontend...
start "VIGIL Frontend" cmd /k "cd frontend && npm run dev"

timeout /t 5 /nobreak >nul

start http://localhost:5173

exit