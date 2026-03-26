@echo off
echo =========================================
echo Angular Messaging Application Setup
echo =========================================

REM Check if node_modules exists
if not exist "node_modules\" (
    echo Installing dependencies...
    call npm install
    if errorlevel 1 (
        echo Error: Failed to install dependencies
        pause
        exit /b 1
    )
) else (
    echo Dependencies already installed.
)

REM Check Angular CLI
where ng >nul 2>nul
if errorlevel 1 (
    echo Installing Angular CLI globally...
    call npm install -g @angular/cli@17
    if errorlevel 1 (
        echo Error: Failed to install Angular CLI
        pause
        exit /b 1
    )
)

echo.
echo =========================================
echo Starting Development Server
echo =========================================
echo.
echo Application will be available at:
echo http://localhost:4200
echo.
echo Press Ctrl+C to stop the server
echo.

REM Start the development server
call ng serve --port 4200 --open
