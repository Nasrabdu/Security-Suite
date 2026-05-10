#!/bin/bash
# Pentest Platform — start both backend and frontend servers
# Frontend must be served via HTTP (not file://) for session cookies to work

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Kill any existing instances on these ports
fuser -k 5000/tcp 2>/dev/null || true
fuser -k 8080/tcp 2>/dev/null || true
sleep 1

# Start Flask backend
cd "$SCRIPT_DIR/pentest-platform/backend"
python3 app.py &
BACKEND_PID=$!

# Give backend a moment to initialise
sleep 2

# Start frontend HTTP server
cd "$SCRIPT_DIR"
python3 -m http.server 8080 --bind 127.0.0.1 &
FRONTEND_PID=$!

echo ""
echo "========================================"
echo "  Pentest Platform is running!"
echo ""
echo "  Open in browser:"
echo "  http://localhost:8080/signin.html"
echo ""
echo "  Admin email: admin@security.com"
echo "  Admin password: read ADMIN_PASSWORD from pentest-platform/backend/.env"
echo "========================================"
echo "  Press Ctrl+C to stop all servers"
echo ""

# Trap Ctrl+C to cleanly stop both processes
trap "echo ''; echo 'Stopping servers...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

wait $BACKEND_PID $FRONTEND_PID
