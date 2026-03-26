#!/bin/bash
# Test Script for Angular Messaging App

echo "==================================="
echo "Angular Messaging App Test Suite"
echo "==================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Base URLs
ANGULAR_URL="http://localhost:4200"
API_URL="https://spear-exchange.lenny-paz123.workers.dev"

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Function to print test results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ $2${NC}"
        ((TESTS_FAILED++))
    fi
}

# Function to test API endpoint
test_api() {
    echo -e "${YELLOW}Testing: $1${NC}"
    response=$(curl -s -o /dev/null -w "%{http_code}" "$2")
    if [ "$response" = "$3" ]; then
        print_result 0 "$1 - Status $response"
    else
        print_result 1 "$1 - Expected $3, got $response"
    fi
}

echo "1. Testing API Endpoints"
echo "------------------------"

# Test API root
test_api "API Root" "$API_URL" "200"

# Test auth endpoint (should return 401 without auth)
test_api "Auth Check (No Token)" "$API_URL/api/me" "401"

# Test CORS preflight
echo -e "${YELLOW}Testing: CORS Preflight${NC}"
cors_response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X OPTIONS \
    -H "Origin: https://lennypaz.github.io" \
    -H "Access-Control-Request-Method: POST" \
    "$API_URL/api/login")
if [ "$cors_response" = "204" ]; then
    print_result 0 "CORS Preflight - Status 204"
else
    print_result 1 "CORS Preflight - Expected 204, got $cors_response"
fi

echo ""
echo "2. Testing Angular Build"
echo "------------------------"

# Check if Angular app is built
if [ -d "dist/angular-messaging" ]; then
    print_result 0 "Angular build directory exists"
    
    # Check for main files
    if [ -f "dist/angular-messaging/index.html" ]; then
        print_result 0 "index.html found"
    else
        print_result 1 "index.html not found"
    fi
    
    if ls dist/angular-messaging/main*.js 1> /dev/null 2>&1; then
        print_result 0 "main.js bundle found"
    else
        print_result 1 "main.js bundle not found"
    fi
else
    echo -e "${YELLOW}Build directory not found. Run 'npm run build' first${NC}"
fi

echo ""
echo "3. Testing SCSS Compilation"
echo "---------------------------"

# Check if styles compiled
if [ -f "src/app/messaging/messaging.component.scss" ]; then
    # Check for mobile menu styles
    if grep -q "mobile-overlay" src/app/messaging/messaging.component.scss; then
        print_result 0 "Mobile overlay styles found"
    else
        print_result 1 "Mobile overlay styles missing"
    fi
    
    if grep -q "mobile-sidebar" src/app/messaging/messaging.component.scss; then
        print_result 0 "Mobile sidebar styles found"
    else
        print_result 1 "Mobile sidebar styles missing"
    fi
    
    # Check for responsive breakpoints
    if grep -q "@media (max-width: 1154px)" src/app/messaging/messaging.component.scss; then
        print_result 0 "Responsive breakpoints found"
    else
        print_result 1 "Responsive breakpoints missing"
    fi
fi

echo ""
echo "4. Testing TypeScript Compilation"
echo "---------------------------------"

# Run TypeScript compiler check
echo -e "${YELLOW}Running TypeScript compiler check...${NC}"
cd "$(dirname "$0")"
npx tsc --noEmit 2>/dev/null
if [ $? -eq 0 ]; then
    print_result 0 "TypeScript compilation successful"
else
    print_result 1 "TypeScript compilation errors found"
fi

echo ""
echo "5. Testing Socket.io Integration"
echo "--------------------------------"

# Check if Socket.io is imported in worker.js
if grep -q "import { Server } from 'socket.io'" ../../spear-exchange/src/worker.js; then
    print_result 0 "Socket.io import found in worker.js"
else
    print_result 1 "Socket.io import missing in worker.js"
fi

if grep -q "handleSocketIO" ../../spear-exchange/src/worker.js; then
    print_result 0 "Socket.io handler found in worker.js"
else
    print_result 1 "Socket.io handler missing in worker.js"
fi

echo ""
echo "6. Testing Dependencies"
echo "-----------------------"

# Check package.json for required dependencies
deps=("socket.io-client" "@angular/common" "@angular/core" "@angular/router" "rxjs")
for dep in "${deps[@]}"; do
    if grep -q "\"$dep\"" package.json; then
        print_result 0 "Dependency '$dep' found"
    else
        print_result 1 "Dependency '$dep' missing"
    fi
done

echo ""
echo "7. Testing Environment Files"
echo "----------------------------"

if [ -f "src/environments/environment.ts" ]; then
    print_result 0 "Development environment file exists"
else
    print_result 1 "Development environment file missing"
fi

if [ -f "src/environments/environment.prod.ts" ]; then
    print_result 0 "Production environment file exists"
else
    print_result 1 "Production environment file missing"
fi

echo ""
echo "==================================="
echo "Test Results Summary"
echo "==================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✨${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed. Please review the issues above.${NC}"
    exit 1
fi
