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
if ($n -gt 0) { Write-Host "Unblocked $n file(s). You can start MailTrace AI now." -ForegroundColor Green }
else { Write-Host "No blocked files found - nothing to do. (If the app still fails, see RUN.txt.)" -ForegroundColor Yellow }
Write-Host "Folder: $root"
