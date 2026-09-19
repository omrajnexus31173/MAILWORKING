@echo off
rem  MailTrace AI - start the UPDATED engine (v1.3.0) and open the console in your browser.
rem  Use this if the desktop window cannot start (e.g. .NET / WebView2 is unavailable).
rem  Requires Python 3.11+ with: fastapi uvicorn networkx dnspython requests python-multipart tldextract reportlab
pushd "%~dp0MAILWORKING\MailTrace AI\_internal\backend"
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found on PATH. Install Python 3.11+ and the packages listed in RUN.txt.
  pause
  exit /b 1
)
start "" cmd /c "timeout /t 5 >nul & start "" http://localhost:8000"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
