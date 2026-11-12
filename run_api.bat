@echo off
REM Start the PhishGraph API on http://127.0.0.1:8000 (keep this window open while browsing)
cd /d "%~dp0"
".venv\Scripts\python.exe" -m uvicorn api.main:app --host 127.0.0.1 --port 8000
pause
