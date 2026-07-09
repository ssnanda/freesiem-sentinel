@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0create-ddev-site-from-synchy-export.ps1"

if errorlevel 1 (
  echo.
  echo Script failed.
  pause
  exit /b 1
)

echo.
pause
