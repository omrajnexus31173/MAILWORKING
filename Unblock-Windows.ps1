# MailTrace AI - remove the Windows "Mark of the Web" (Zone.Identifier) from this folder.
#
# Windows marks every file extracted from a downloaded .zip as "came from the internet".
# The .NET Framework then refuses to load the marked Python.Runtime.dll / WebView2 assemblies
# the MailTrace AI window needs, and the app fails to open with:
#     "Failed to resolve Python.Runtime.Loader.Initialize"
# Deleting the hidden Zone.Identifier streams is exactly what Explorer's "Unblock" checkbox or
# PowerShell's Unblock-File do. Run this once after extracting, then start MailTrace AI.
$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$files = Get-ChildItem -LiteralPath $root -Recurse -Force -File
$n = 0
foreach ($f in $files) {
  $stream = Get-Item -LiteralPath $f.FullName -Stream Zone.Identifier
  if ($stream) {
    Remove-Item -LiteralPath $f.FullName -Stream Zone.Identifier
    $n++
  }
}
# Fallback for systems where the -Stream parameter is unavailable: Unblock-File
# does the same thing (it deletes the Zone.Identifier alternate data stream).
if ($n -eq 0) {
  try {
    Get-ChildItem -LiteralPath $root -Recurse -Force -File | Unblock-File
  } catch { }
}
if ($n -gt 0) { Write-Host "Unblocked $n file(s). You can start MailTrace AI now." -ForegroundColor Green }
else { Write-Host "No blocked files found - nothing to do. (If the app still fails, see RUN.txt.)" -ForegroundColor Yellow }
Write-Host "Folder: $root"

# Quick runtime sanity line: the file that must ship with the EXE.
$app = $null
foreach ($c in @($root, (Join-Path $root "MAILWORKING\MailTrace AI"), (Join-Path $root "MailTrace AI"))) {
  if (Test-Path (Join-Path $c "MailTrace AI.exe")) { $app = $c; break }
}
if ($app) {
  $bl = Join-Path $app "_internal\base_library.zip"
  if (Test-Path $bl) {
    Write-Host ("Runtime: base_library.zip present ({0:N0} bytes)" -f @((Get-Item -LiteralPath $bl).Length)) -ForegroundColor Green
  } else {
    Write-Host "Runtime: base_library.zip MISSING - re-extract the zip, the app cannot start without it." -ForegroundColor Red
  }
}
