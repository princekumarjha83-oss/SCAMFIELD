@echo off
echo ========================================================
echo       Starting ScamShield AI Full-Stack Platform        
echo ========================================================

echo [*] Starting FastAPI Backend on http://127.0.0.1:8000...
start "ScamShield Backend" cmd /k "backend\venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"

echo [*] Starting Vite React Frontend on http://127.0.0.1:5173...
cd frontend
start "ScamShield Frontend" cmd /k "npm run dev -- --host 127.0.0.1 --port 5173"

echo.
echo [!] ScamShield AI is active!
echo     - Frontend Dashboard: http://127.0.0.1:5173
echo     - Backend API Docs:   http://127.0.0.1:8000/docs
echo ========================================================
