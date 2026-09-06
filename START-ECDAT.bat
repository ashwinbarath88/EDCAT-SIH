@echo off
setlocal EnableExtensions
cd /d "%~dp0backend"
title ECDAT — Local Cryptographic Intelligence Core
color 0B
cls
echo.
echo  ============================================================
echo      ECDAT 7.0  ^|  CRYPTOGRAPHIC DISCOVERY RADAR
echo  ============================================================
echo.
where py >nul 2>nul && set "PY=py"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
 echo [ERROR] Python was not found.
 echo Install Python 3.10+ and enable "Add Python to PATH".
 pause
 exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
 echo [1/3] Creating local Python environment...
 %PY% -m venv .venv || (echo [ERROR] Could not create venv.&pause&exit /b 1)
)
echo [2/3] Installing / checking dependencies...
call ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt || (echo [ERROR] Dependency installation failed.&pause&exit /b 1)
echo [3/3] Starting ECDAT...
echo.
echo     OPEN: http://127.0.0.1:5050
echo     KEEP THIS WINDOW OPEN.
echo.
start "ECDAT Browser" http://127.0.0.1:5050
".venv\Scripts\python.exe" app.py
pause
