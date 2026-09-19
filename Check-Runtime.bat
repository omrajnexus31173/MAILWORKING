@echo off
rem  MailTrace AI - verify the packaged Python runtime (base_library.zip,
rem  python312.dll, extension modules, backend, frontend). Paths are relative
rem  to this BAT, so it works from the zip root or next to the .exe.
pushd "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Check-Runtime.ps1"
echo.
pause
