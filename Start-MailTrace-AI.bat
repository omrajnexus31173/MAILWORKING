@echo off
rem  MailTrace AI - unblock (if needed) and start the desktop app.
pushd "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Unblock-Windows.ps1"
echo Starting MailTrace AI...
start "" "%~dp0MAILWORKING\MailTrace AI\MailTrace AI.exe"
