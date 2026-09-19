@echo off
rem =====================================================================
rem  MailTrace AI - unblock (if needed) and start the desktop app.
rem
rem  This file works from EITHER location:
rem     zip root                      -> starts MAILWORKING\MailTrace AI\MailTrace AI.exe
rem     inside MAILWORKING\MailTrace AI\ -> starts the .exe right beside it
rem  Every path is resolved from the BAT's own folder (%~dp0).
rem =====================================================================
setlocal
pushd "%~dp0"

set "EXE=%~dp0MailTrace AI.exe"
if not exist "%EXE%" set "EXE=%~dp0MAILWORKING\MailTrace AI\MailTrace AI.exe"
if not exist "%EXE%" set "EXE="
if not defined EXE (
  for /r "%~dp0" %%F in ("MailTrace AI.exe") do if not defined EXE set "EXE=%%~F"
)
if not defined EXE (
  echo.
  echo  ERROR: "MailTrace AI.exe" was not found under:
  echo         %~dp0
  echo  Extract the whole zip first and keep the folder structure.
  echo.
  pause
  exit /b 1
)

echo  MailTrace AI launcher
echo  ------------------------------------------------------------
echo  Application : %EXE%
echo  Runtime     : %~dp0_internal   (or the _internal folder beside it)
echo.

if exist "%~dp0Unblock-Windows.ps1" (
  echo  [1/2] Clearing Windows "Mark of the Web" ^(Zone.Identifier^) ...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Unblock-Windows.ps1"
) else (
  echo  [1/2] Unblock-Windows.ps1 not found - skipping ^(only needed right after download^)
)

echo  [2/2] Starting MailTrace AI ...
start "" "%EXE%"

echo.
echo  If nothing appears, run  Check-Runtime.bat  - it verifies the packaged
echo  Python runtime (base_library.zip, python312.dll, extension modules).
timeout /t 3 >nul
endlocal
