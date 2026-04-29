@echo off
setlocal

if "%PORT%"=="" set "PORT=3000"

echo Checking port %PORT%...
set "FOUND="
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
    set "FOUND=1"
    echo Stopping dashboard process on port %PORT% ^(PID %%a^)...
    taskkill /F /PID %%a >nul 2>nul
)

if not defined FOUND echo No process is listening on port %PORT%.
