#!/usr/bin/env bash
# ============================================================
# Security Suite Pentest Platform - Startup Script
# ============================================================
# Usage:
#   export GEMINI_API_KEY="your-gemini-key-here"
#   chmod +x start_platform.sh
#   ./start_platform.sh
#
# Then open GPgit/signin.html in your browser.
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/pentest-platform/backend"

echo ""
echo "=============================================="
echo "  🛡  Security Suite Pentest Platform v3.0"
echo "=============================================="

# Check nmap
if ! command -v nmap &> /dev/null; then
    echo "⚠  WARNING: nmap not found. Install with: sudo apt-get install nmap"
fi

# Check python venv
VENV="$BACKEND_DIR/venv"
if [ ! -d "$VENV" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

echo "📦 Installing/checking dependencies..."
pip install -q -r "$BACKEND_DIR/requirements.txt"

echo ""
if [ -n "$GEMINI_API_KEY" ]; then
    echo "✓ Gemini API key detected — AI features enabled"
else
    echo "⚠  GEMINI_API_KEY not set — AI will use rule-based fallback"
    echo "   Get a free key at: https://aistudio.google.com/"
    echo "   Then run: export GEMINI_API_KEY='your-key'"
fi

echo "Stopping any existing platform servers..."
fuser -k 5000/tcp 2>/dev/null || true
fuser -k 5500/tcp 2>/dev/null || true

echo ""
echo "🚀 Starting frontend server on port 5500..."
cd "$SCRIPT_DIR"
python3 -m http.server 5500 > /dev/null 2>&1 &
FRONT_PID=$!

trap "echo 'Stopping servers...'; kill $FRONT_PID 2>/dev/null; exit" EXIT INT TERM

echo ""
echo "🚀 Starting backend server on port 5000..."
echo "========================================================================"
echo "   👉 OPEN THIS URL IN YOUR BROWSER: http://localhost:5500/signin.html"
echo "   (Do not open the file directly via file://)"
echo "   Admin email: admin@security.com"
echo "   Admin password: read ADMIN_PASSWORD from pentest-platform/backend/.env"
echo "========================================================================"
echo ""
echo "Press Ctrl+C to stop both servers."
echo ""

cd "$BACKEND_DIR"
python app.py
