@echo off
rem =====================================================================
rem  MailTrace AI - run the engine and open the console in a browser.
rem
rem  Paths are resolved from this BAT's own folder (%~dp0), so it works
rem  from the zip root and from inside MAILWORKING\MailTrace AI\.
rem
rem  1. If Python is installed it starts the engine on http://127.0.0.1:8000
rem     and opens the console in your default browser.
rem  2. If Python is NOT installed it starts the packaged EXE instead
rem     (self-contained: it runs the same engine in-process on a random
rem     loopback port and shows the console in its own window).
rem =====================================================================
setlocal
pushd "%~dp0"

set "APPDIR=%~dp0"
if not exist "%APPDIR%_internal\backend\main.py" set "APPDIR=%~dp0MAILWORKING\MailTrace AI\"
if not exist "%APPDIR%_internal\backend\main.py" set "APPDIR="
if not defined APPDIR (
  for /r "%~dp0" %%F in ("main.py") do if not defined APPDIR (
    if exist "%%~dpF_internal\backend\main.py" set "APPDIR=%%~dpF"
  )
)
if not defined APPDIR (
  echo  ERROR: could not locate "MailTrace AI\_internal\backend" under %~dp0
  pause
  exit /b 1
)
set "BACKEND=%APPDIR%_internal\backend"
set "EXE=%APPDIR%MailTrace AI.exe"
echo  MailTrace AI - engine launcher
echo  ------------------------------------------------------------
echo  Backend : %BACKEND%
echo.

where python >nul 2>nul
if errorlevel 1 goto NOPYTHON

echo  Python found - starting the engine on http://127.0.0.1:8000 ...
start "" cmd /c "timeout /t 5 >nul & start "" http://127.0.0.1:8000"
pushd "%BACKEND%"
python -m uvicorn main:app --host 127.0.0.1 --port 8000
popd
goto END

:NOPYTHON
echo  Python was not found on PATH - using the packaged application instead.
echo  The EXE carries its own Python runtime; no installation is required.
if exist "%EXE%" (
  if exist "%~dp0Unblock-Windows.ps1" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Unblock-Windows.ps1"
  start "" "%EXE%"
  echo  MailTrace AI started. The console opens in the application window.
) else (
  echo  ERROR: neither Python nor "%EXE%" was found.
)
echo.

:END
endlocal
