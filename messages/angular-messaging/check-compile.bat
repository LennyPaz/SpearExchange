@echo off
echo =========================================
echo Checking Angular Compilation
echo =========================================

REM Check if node_modules exists
if not exist "node_modules\" (
    echo Installing dependencies first...
    call npm install
)

echo.
echo Running TypeScript compilation check...
echo.

REM Run Angular compilation check (just build without output)
call ng build --configuration development

if errorlevel 1 (
    echo.
    echo =========================================
    echo Compilation Failed - Check errors above
    echo =========================================
) else (
    echo.
    echo =========================================
    echo Compilation Successful!
    echo =========================================
    echo You can now run: npm start
)

pause
