@echo off
setlocal
title VIGIL AI Launcher

REM Save this BAT file in the VIGIL-AI project root.
set "ROOT=%~dp0"
set "PYTHON=%ROOT%.venv\Scripts\python.exe"
set "FRONTEND=%ROOT%frontend"

echo ==========================================
echo          VIGIL AI - Launcher
echo ==========================================
echo Project: %ROOT%
echo.

if not exist "%PYTHON%" (
    echo [ERROR] Python virtual environment not found:
    echo         %PYTHON%
    echo Update PYTHON in this BAT file if your environment is elsewhere.
    pause
    exit /b 1
)

if not exist "%FRONTEND%\package.json" (
    echo [ERROR] Frontend package.json not found at:
    echo         %FRONTEND%
    pause
    exit /b 1
)

if not exist "%ROOT%api.py" (
    echo [ERROR] api.py was not found in the project root.
    echo This launcher expects the backend entry point to be api.py.
    echo Edit the BACKEND command in this BAT file if your backend starts differently.
    pause
    exit /b 1
)

if not exist "%FRONTEND%\node_modules" (
    echo [INFO] Frontend dependencies are missing. Installing with npm...
    pushd "%FRONTEND%"
    call npm install
    if errorlevel 1 (
        popd
        echo [ERROR] npm install failed.
        pause
        exit /b 1
    )
    popd
)

echo [1/3] Starting VIGIL AI backend...
start "VIGIL AI Backend" /D "%ROOT%" cmd /k ""%PYTHON%" "%ROOT%api.py""

timeout /t 3 /nobreak >nul

echo [2/3] Starting VIGIL AI frontend...
start "VIGIL AI Frontend" /D "%FRONTEND%" cmd /k "npm run dev"

echo [3/3] Opening Chrome...
timeout /t 3 /nobreak >nul
where chrome >nul 2>nul
if not errorlevel 1 (
    start "" chrome "http://localhost:5173" "chrome://extensions/"
) else (
    if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
        start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" "http://localhost:5173" "chrome://extensions/"
    ) else if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
        start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" "http://localhost:5173" "chrome://extensions/"
    ) else (
        echo [WARN] Chrome was not found automatically. Open Chrome manually.
        echo Frontend: http://localhost:5173
        echo Extensions page: chrome://extensions/
    )
)

echo.
echo VIGIL AI startup commands have been launched.
echo Keep the Backend and Frontend terminal windows open.
echo Your already-installed Chrome extension should remain enabled in Chrome.
echo If the frontend uses a different port, use the URL shown in its terminal.
echo.
pause
endlocal
