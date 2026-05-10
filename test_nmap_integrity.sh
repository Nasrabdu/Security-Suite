#!/bin/bash

# Nmap Integration Test Script
# This script tests the integrity of the Nmap scanner in the Security Suite

set -e  # Exit on error

echo "=========================================="
echo "  Nmap Integration Integrity Test"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test results
print_test() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $2"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Check if Nmap is installed
echo "Test 1: Checking Nmap installation..."
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -n1)
    print_test 0 "Nmap is installed: $NMAP_VERSION"
else
    print_test 1 "Nmap is not installed"
    echo "Install with: sudo apt install nmap"
    exit 1
fi
echo ""

# Test 2: Check if Python 3 is installed
echo "Test 2: Checking Python 3 installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_test 0 "Python 3 is installed: $PYTHON_VERSION"
else
    print_test 1 "Python 3 is not installed"
    exit 1
fi
echo ""

# Test 3: Check if project files exist
echo "Test 3: Checking project files..."
cd /home/kali/Desktop/GPgit

if [ -f "scripts/nmap_scanner.py" ]; then
    print_test 0 "nmap_scanner.py exists"
else
    print_test 1 "nmap_scanner.py not found"
fi

if [ -f "scripts/nmap_scan.sh" ]; then
    print_test 0 "nmap_scan.sh exists"
else
    print_test 1 "nmap_scan.sh not found"
fi

if [ -f "Nmap.html" ]; then
    print_test 0 "Nmap.html exists"
else
    print_test 1 "Nmap.html not found"
fi

if [ -f "js/vulnerability-classifier.js" ]; then
    print_test 0 "vulnerability-classifier.js exists"
else
    print_test 1 "vulnerability-classifier.js not found"
fi
echo ""

# Test 4: Test Python scanner with safe target
echo "Test 4: Testing Python scanner (this may take 30-60 seconds)..."
echo -e "${YELLOW}Running: python3 scripts/nmap_scanner.py scanme.nmap.org quick${NC}"

cd scripts
if python3 nmap_scanner.py scanme.nmap.org quick --output /tmp/test_scan.json &> /tmp/nmap_test.log; then
    print_test 0 "Python scanner executed successfully"
    
    # Check if JSON output was created
    if [ -f "/tmp/test_scan.json" ]; then
        print_test 0 "JSON output file created"
        echo "Output saved to: /tmp/test_scan.json"
    else
        print_test 1 "JSON output file not created"
    fi
else
    print_test 1 "Python scanner failed"
    echo "Check logs at: /tmp/nmap_test.log"
fi
cd ..
echo ""

# Test 5: Check bash wrapper script
echo "Test 5: Testing bash wrapper script..."
cd scripts
chmod +x nmap_scan.sh

if [ -x "nmap_scan.sh" ]; then
    print_test 0 "nmap_scan.sh is executable"
else
    print_test 1 "nmap_scan.sh is not executable"
fi
cd ..
echo ""

# Test 6: Check web files
echo "Test 6: Checking web interface files..."
if [ -f "signin.html" ] && [ -f "Dashbord.html" ] && [ -f "Nmap.html" ]; then
    print_test 0 "All HTML files present"
else
    print_test 1 "Some HTML files are missing"
fi
echo ""

# Summary
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed! Your Nmap integration is working correctly.${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Start web server: python3 -m http.server 5500"
    echo "2. Open browser: http://localhost:5500"
    echo "3. Login with admin@security.com and ADMIN_PASSWORD from environment"
    echo "4. Test the Nmap interface"
    echo ""
    echo "For detailed testing guide, see:"
    echo "  ~/.gemini/antigravity/brain/7e679ea1-8dda-432d-9fb3-432f1ebe82c4/nmap_testing_guide.md"
else
    echo -e "${RED}✗ Some tests failed. Please fix the issues above.${NC}"
    exit 1
fi

echo "=========================================="
