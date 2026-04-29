@echo off
setlocal

cd /d "%~dp0"

if "%PORT%"=="" set "PORT=3000"
set "BUNDLED_NODE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
set "NODE_CMD=node"

where node >nul 2>nul
if errorlevel 1 (
    if exist "%BUNDLED_NODE%" (
        set "NODE_CMD=%BUNDLED_NODE%"
    ) else (
        echo Node.js was not found in PATH and the bundled runtime was not found.
        echo Install Node.js 18+ or start with the bundled runtime path manually.
        exit /b 1
    )
)

echo Checking port %PORT%...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
    echo Stopping existing dashboard process on port %PORT% ^(PID %%a^)...
    taskkill /F /PID %%a >nul 2>nul
)

echo Starting CTI Dashboard at http://localhost:%PORT%
"%NODE_CMD%" server\index.js
