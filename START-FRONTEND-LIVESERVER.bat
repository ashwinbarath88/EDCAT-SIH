@echo off
cd /d "%~dp0frontend"
where code >nul 2>nul && code index.html
start "ECDAT Frontend" http://127.0.0.1:5050
