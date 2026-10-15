@echo off
title NetPulse Cyber NOC v4.0 — Campus Network Monitor
color 0A

echo.
echo  =====================================================
echo   NETPULSE CYBER NOC v4.0 — Campus Network Monitor
echo  =====================================================
echo.
echo  [*] Starting Gateway Proxy on 0.0.0.0:8088
echo  [*] Starting Web Dashboard  on http://localhost:5000
echo.
echo  Mobile Setup: Connect phone to PC Hotspot
echo               Proxy Host : 192.168.137.1
echo               Proxy Port : 8088
echo.
echo  Dashboard: Open http://localhost:5000 in browser
echo.
echo  =====================================================
echo.

cd /d "%~dp0"

:: Open browser after 2 seconds in background
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:5000"

:: Start NetPulse server in foreground (press Ctrl+C to stop)
python server.py
pause
