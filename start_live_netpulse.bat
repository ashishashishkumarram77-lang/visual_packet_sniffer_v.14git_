@echo off
title NetPulse v4.0 Live Server & Tunnel Launcher
echo =====================================================================
echo   NetPulse v4.0: Starting Crash-Proof Server + Live HTTPS Tunnel...
echo =====================================================================
start "NetPulse Python Server" cmd /k "python app.py"
timeout /t 3 /nobreak >nul
echo Starting Cloudflare Live Tunnel on IPv4 (127.0.0.1:5000)...
cloudflared tunnel --url http://127.0.0.1:5000
pause
