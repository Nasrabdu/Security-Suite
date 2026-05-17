#!/bin/bash
# Security Suite - Setup Script (Linux/Mac)

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║        🛡️  Security Suite - Setup               ║${NC}"
echo -e "${CYAN}║     AI-Powered Penetration Testing Platform     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ─── Check Docker ───────────────────────────────────────
echo -e "[1/4] Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is NOT installed!${NC}"
    echo "👉 Download from: https://www.docker.com/products/docker-desktop/"
    exit 1
fi
echo -e "${GREEN}✅ Docker found.${NC}"
echo ""

# ─── Check .env file ────────────────────────────────────
echo -e "[2/4] Checking .env file..."
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  .env file not found. Creating from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✅ .env created from .env.example${NC}"
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ⚠️  IMPORTANT: Edit .env before continuing!    ║${NC}"
    echo -e "${YELLOW}║                                                  ║${NC}"
    echo -e "${YELLOW}║  Set your GEMINI_API_KEY in .env file           ║${NC}"
    echo -e "${YELLOW}║  Get a free key from:                           ║${NC}"
    echo -e "${YELLOW}║  https://aistudio.google.com/app/apikey         ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Opening .env in nano editor..."
    sleep 1
    nano .env
else
    echo -e "${GREEN}✅ .env file found.${NC}"
fi
echo ""

# ─── Build and Start ────────────────────────────────────
echo -e "[3/4] Building and starting containers..."
echo -e "${YELLOW}⏳ This may take 5-10 minutes on first run...${NC}"
echo ""
docker-compose up -d --build
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Failed to start containers!${NC}"
    echo "Run: docker-compose logs"
    exit 1
fi
echo ""

# ─── Done ───────────────────────────────────────────────
echo -e "[4/4] Waiting for services to be ready..."
sleep 5

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           ✅ Setup Complete!                     ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}║  🛡️  Security Suite:  http://localhost:5000     ║${NC}"
echo -e "${GREEN}║  🎯  DVWA:            http://localhost:8080     ║${NC}"
echo -e "${GREEN}║  🗄️  pgAdmin:         http://localhost:5050     ║${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}║  Default Admin:  admin@security.com             ║${NC}"
echo -e "${GREEN}║  Password:       (see ADMIN_PASSWORD in .env)   ║${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Open browser
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:5000
elif command -v open &> /dev/null; then
    open http://localhost:5000
fi

echo ""
echo "To stop the platform, run: docker-compose down"
echo ""
