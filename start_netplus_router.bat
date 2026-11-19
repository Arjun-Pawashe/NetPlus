@echo off
title NetPlus Router Gateway v5.0 — Starting...
color 0A

echo.
echo  ================================================================
echo   NETPLUS ROUTER GATEWAY v5.0 — Windows ICS + TL-WR740N (AP Mode)
echo  ================================================================
echo.

:: Check for Administrator privileges (needed for Port 53, Port 80, Npcap & netsh firewall)
net session >nul 2>&1
if errorlevel 1 (
    echo  [WARN] Not running as Administrator!
    echo         DNS Sinkhole port 53, Captive Portal port 80, Npcap sniffing,
    echo         and Windows Firewall quota rules require an Administrator terminal.
    echo.
)

if not defined NETPLUS_GATEWAY_IP set "NETPLUS_GATEWAY_IP=192.168.137.1"
if not defined NETPLUS_CLIENT_NETWORK set "NETPLUS_CLIENT_NETWORK=192.168.137.0/24"
if not defined NETPLUS_UPSTREAM_DNS set "NETPLUS_UPSTREAM_DNS=8.8.8.8"
if not defined NETPLUS_ROUTER_IP set "NETPLUS_ROUTER_IP=192.168.137.2"
if not defined NETPLUS_ROUTER_POLL set "NETPLUS_ROUTER_POLL=0"

echo  [*] Gateway IP       : %NETPLUS_GATEWAY_IP%
echo  [*] Client Subnet    : %NETPLUS_CLIENT_NETWORK%
echo  [*] Upstream DNS     : %NETPLUS_UPSTREAM_DNS%
echo  [*] Dashboard URL    : http://localhost:5000
echo  [*] TL-WR740N Poller : %NETPLUS_ROUTER_POLL% ^(%NETPLUS_ROUTER_IP%^)
echo.
echo  Wiring: Internet -^> Host PC ^(ICS^) -^> Ethernet -^> TL-WR740N LAN Port ^(DHCP OFF^)
echo.
echo  ================================================================
echo.

cd /d "%~dp0"

py -3 --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python 3 was not found. Install Python 3.10+ and try again.
    pause
    exit /b 1
)

start "NetPlus Router Gateway" /B py -3 server.py
if errorlevel 1 (
    echo  [ERROR] Could not launch NetPlus Router Gateway.
    pause
    exit /b 1
)

ping 127.0.0.1 -n 4 >nul
start "" "http://localhost:5000"

echo  [OK] Server launched. Browser opening http://localhost:5000 ...
echo  [OK] Close this window or press CTRL+C to stop.
echo.
pause
