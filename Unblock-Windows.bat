@echo off
rem =====================================================================
rem  MailTrace AI - remove Windows' "Mark of the Web" from every file here.
rem  Run ONCE (double-click) right after extracting the zip.
rem  Works from the zip root and from inside MAILWORKING\MailTrace AI\.
rem =====================================================================
setlocal
pushd "%~dp0"

if exist "%~dp0Unblock-Windows.ps1" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Unblock-Windows.ps1"
) else (
  echo Unblock-Windows.ps1 is missing next to this BAT - nothing was changed.
)

set "EXE=%~dp0MailTrace AI.exe"
if not exist "%EXE%" set "EXE=%~dp0MAILWORKING\MailTrace AI\MailTrace AI.exe"
echo.
if exist "%EXE%" (echo You can now start:  "%EXE%") else (echo Start: MAILWORKING\MailTrace AI\MailTrace AI.exe)
echo            or double-click Start-MailTrace-AI.bat
echo.
pause
endlocal
