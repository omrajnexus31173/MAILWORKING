@echo off
rem  MailTrace AI - remove Windows' "Mark of the Web" from every file in this folder.
rem  Run this ONCE (double-click) right after extracting the zip, before starting the app.
pushd "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Unblock-Windows.ps1"
echo.
echo Done. You can now start:  MAILWORKING\MailTrace AI\MailTrace AI.exe
pause
