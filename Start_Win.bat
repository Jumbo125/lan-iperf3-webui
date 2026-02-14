@echo off
setlocal

:: Admin check (kein UAC prompt)
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo [FEHLER] Administratorrechte werden benoetigt!
  echo Bitte Rechtsklick auf die .bat ^> "Als Administrator ausfuehren".
  echo.
  pause
  exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Setup_IP\ip_setup.ps1"
pause
