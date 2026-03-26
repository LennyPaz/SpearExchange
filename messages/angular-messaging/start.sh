#!/bin/bash

echo "========================================="
echo "Angular Messaging Application Setup"
echo "========================================="

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install dependencies"
        exit 1
    fi
else
    echo "Dependencies already installed."
fi

# Check Angular CLI
if ! command -v ng &> /dev/null; then
    echo "Installing Angular CLI globally..."
    npm install -g @angular/cli@17
    if [ $? -ne 0 ]; then
        echo "Error: Failed to install Angular CLI"
        exit 1
    fi
fi

echo ""
echo "========================================="
echo "Starting Development Server"
echo "========================================="
echo ""
echo "Application will be available at:"
echo "http://localhost:4200"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the development server
ng serve --port 4200 --open
