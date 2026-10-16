# ScamShield AI - PowerShell Unified Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "      Starting ScamShield AI Full-Stack Platform        " -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Start Backend in separate window
Write-Host "[*] Launching FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "backend\venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"

# 2. Start Frontend in separate window
Write-Host "[*] Launching Vite React Frontend on http://127.0.0.1:5173..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location frontend; npm run dev -- --host 127.0.0.1 --port 5173"

Write-Host ""
Write-Host "[+] ScamShield AI Platform is running:" -ForegroundColor Green
Write-Host "    - Frontend Dashboard: http://127.0.0.1:5173" -ForegroundColor White
Write-Host "    - Swagger API Docs:   http://127.0.0.1:8000/docs" -ForegroundColor White
Write-Host "========================================================" -ForegroundColor Cyan
