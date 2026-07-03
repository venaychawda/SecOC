@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ================================================
echo   SecOC Simulation - Setup and Launch
echo ================================================
echo.

REM --- 0. Locate a Python interpreter -------------------------------------
where python >nul 2>nul
if not errorlevel 1 (
    set "PY_CMD=python"
) else (
    where py >nul 2>nul
    if not errorlevel 1 (
        set "PY_CMD=py"
    ) else (
        echo ERROR: Python was not found on PATH.
        echo Install Python 3.11+ from https://www.python.org/downloads/
        echo and make sure "Add python.exe to PATH" is checked, then re-run this script.
        pause
        exit /b 1
    )
)

REM --- 1. Create the virtual environment if it does not exist -------------
if not exist ".venv\Scripts\python.exe" (
    echo [1/5] Creating virtual environment in .venv ...
    %PY_CMD% -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create the virtual environment.
        pause
        exit /b 1
    )
) else (
    echo [1/5] Virtual environment already exists, skipping creation.
)

set "VENV_PY=%~dp0.venv\Scripts\python.exe"

REM --- 2. Upgrade pip -------------------------------------------------------
echo [2/5] Upgrading pip ...
"%VENV_PY%" -m pip install --upgrade pip >nul
if errorlevel 1 (
    echo ERROR: Failed to upgrade pip.
    pause
    exit /b 1
)

REM --- 3. Install dependencies from requirements.txt -----------------------
echo [3/5] Installing dependencies from requirements.txt ...
"%VENV_PY%" -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies from requirements.txt.
    pause
    exit /b 1
)

REM --- 4. Editable install so `sim` / `api` packages resolve for pytest ----
echo [4/5] Installing the project in editable mode (pip install -e .) ...
"%VENV_PY%" -m pip install -e .
if errorlevel 1 (
    echo ERROR: Failed to install the project in editable mode.
    pause
    exit /b 1
)

REM --- 5. Launch the backend and the dashboard server in their own windows -
echo [5/5] Starting the FastAPI backend and the dashboard server ...

start "SecOC Backend (port 8000)" /D "%~dp0" cmd /k "call .venv\Scripts\activate.bat && uvicorn api.main:app --reload --port 8000"
start "SecOC Dashboard (port 3000)" /D "%~dp0" cmd /k "call .venv\Scripts\activate.bat && python -m http.server 3000 --directory docs"

echo Waiting for the backend to come up ...
timeout /t 4 /nobreak >nul

echo Opening the SecOC Live Monitor in your default browser ...
start "" "http://localhost:3000/SecOC_Monitor.html"

echo.
echo ================================================
echo   SecOC is running:
echo     Backend    -^> http://localhost:8000
echo     Dashboard  -^> http://localhost:3000/SecOC_Monitor.html
echo.
echo   Two terminal windows were opened for the backend
echo   and the dashboard server. Close them to stop SecOC.
echo   See USERINFO.md for how to use the dashboard.
echo ================================================
echo.
pause
endlocal
