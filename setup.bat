@echo off
chcp 65001 >nul
title Security Suite - Setup

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║        🛡️  Security Suite - Setup               ║
echo  ║     AI-Powered Penetration Testing Platform     ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: ─── Check Docker ───────────────────────────────────────
echo [1/4] Checking Docker...
docker --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ❌ Docker is NOT installed!
    echo  👉 Download from: https://www.docker.com/products/docker-desktop/
    echo.
    pause
    exit /b 1
)
echo  ✅ Docker found.
echo.

:: ─── Check .env file ────────────────────────────────────
echo [2/4] Checking .env file...
if not exist ".env" (
    echo  ⚠️  .env file not found. Creating from template...
    copy ".env.example" ".env" >nul
    echo  ✅ .env created from .env.example
    echo.
    echo  ╔══════════════════════════════════════════════════╗
    echo  ║  ⚠️  IMPORTANT: Edit .env before continuing!    ║
    echo  ║                                                  ║
    echo  ║  Set your GEMINI_API_KEY in the .env file:      ║
    echo  ║  Get a free key from:                           ║
    echo  ║  https://aistudio.google.com/app/apikey         ║
    echo  ╚══════════════════════════════════════════════════╝
    echo.
    echo  Opening .env for editing...
    timeout /t 2 >nul
    notepad .env
    echo.
    echo  Press any key after saving your API key...
    pause >nul
) else (
    echo  ✅ .env file found.
)
echo.

:: ─── Build and Start ────────────────────────────────────
echo [3/4] Building and starting containers...
echo  ⏳ This may take 5-10 minutes on first run...
echo.
docker-compose up -d --build
if errorlevel 1 (
    echo.
    echo  ❌ Failed to start containers!
    echo  Run: docker-compose logs
    echo.
    pause
    exit /b 1
)
echo.

:: ─── Done ───────────────────────────────────────────────
echo [4/4] Waiting for services to be ready...
timeout /t 5 >nul

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║           ✅ Setup Complete!                     ║
echo  ╠══════════════════════════════════════════════════╣
echo  ║                                                  ║
echo  ║  🛡️  Security Suite:  http://localhost:5000     ║
echo  ║  🎯  DVWA:            http://localhost:8080     ║
echo  ║  🗄️  pgAdmin:         http://localhost:5050     ║
echo  ║                                                  ║
echo  ║  Default Admin:  admin@security.com             ║
echo  ║  Password:       (see ADMIN_PASSWORD in .env)   ║
echo  ║                                                  ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: Open browser
echo  Opening Security Suite in browser...
timeout /t 2 >nul
start http://localhost:5000

echo.
echo  To stop the platform, run: docker-compose down
echo.
pause
