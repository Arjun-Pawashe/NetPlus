@echo off
title NetPulse Cyber NOC v4.0 — Starting...
color 0A

echo.
echo  =====================================================
echo   NETPULSE CYBER NOC v4.0 — Campus Network Monitor
echo  =====================================================
echo.
if not defined NETPLUS_GATEWAY_IP set "NETPLUS_GATEWAY_IP=192.168.137.1"
if not defined NETPLUS_CLIENT_NETWORK set "NETPLUS_CLIENT_NETWORK=192.168.137.0/24"
if not defined NETPLUS_PROXY_PORT set "NETPLUS_PROXY_PORT=8081"

echo  [*] Starting Gateway Proxy on 0.0.0.0:%NETPLUS_PROXY_PORT%
echo  [*] Starting Web Dashboard  on http://localhost:5000
echo.
echo  Router/AP Setup: Share Wi-Fi internet to Ethernet using Windows ICS.
echo                   Connect router LAN port to laptop Ethernet.
echo                   Use router AP mode with its DHCP server disabled.
echo  Proxy Host : %NETPLUS_GATEWAY_IP%
echo               Proxy Port : %NETPLUS_PROXY_PORT%
echo.
echo  Dashboard: Open http://localhost:5000 in browser
echo  Note: Devices need this manual proxy to appear in NetPlus logs.
echo.
echo  =====================================================
echo.

cd /d "%~dp0"

py -3 --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python 3 was not found. Install Python 3 and try again.
    pause
    exit /b 1
)

:: Start server
start "NetPulse Server" /B py -3 server.py
if errorlevel 1 (
    echo  [ERROR] Could not launch the NetPulse server.
    pause
    exit /b 1
)

:: Wait 3 seconds then open browser
ping 127.0.0.1 -n 4 >nul
start "" "http://localhost:5000"

    echo  [OK] Server process launched. Browser opening...
echo  [OK] Press CTRL+C in this window to stop.
echo.

:: Keep window alive while the background server runs
pause
