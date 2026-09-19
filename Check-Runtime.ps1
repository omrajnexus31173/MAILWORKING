# MailTrace AI - verify the PACKAGED WINDOWS RUNTIME is complete.
#
# The PyInstaller bootloader needs these before it can start Python at all:
#   _internal\base_library.zip   Python core modules (codecs, encodings, io, os ...)
#                                MISSING -> "Failed to start embedded python interpreter!"
#   _internal\python312.dll      the embedded interpreter named inside the .exe
#   _internal\*.pyd              compiled standard-library extension modules
#                                (_socket, _ssl, select, _ctypes, unicodedata ...)
# plus the application payload (backend, frontend, models, samples).
#
# Run Check-Runtime.bat (or this script) after extracting - it prints PASS/FAIL per item.

$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# locate the application folder (works from the zip root or next to the .exe)
$app = $null
foreach ($candidate in @($root, (Join-Path $root "MAILWORKING\MailTrace AI"),
                                (Join-Path $root "MailTrace AI"))) {
  if (Test-Path (Join-Path $candidate "MailTrace AI.exe")) { $app = $candidate; break }
}
if (-not $app) {
  $found = Get-ChildItem -LiteralPath $root -Recurse -Filter "MailTrace AI.exe" -File | Select-Object -First 1
  if ($found) { $app = $found.DirectoryName }
}
if (-not $app) {
  Write-Host "FAIL  MailTrace AI.exe was not found under: $root" -ForegroundColor Red
  Write-Host "      Extract the whole zip first and keep the folder structure."
  exit 1
}

$internal = Join-Path $app "_internal"
$fail = 0
function Check($ok, $label, $detail) {
  if ($ok) { Write-Host ("PASS  {0}" -f $label) -ForegroundColor Green; if ($detail) { Write-Host ("        {0}" -f $detail) -ForegroundColor DarkGray } }
  else { Write-Host ("FAIL  {0}" -f $label) -ForegroundColor Red; if ($detail) { Write-Host ("        {0}" -f $detail) -ForegroundColor Yellow }; $script:fail++ }
}

Write-Host ""
Write-Host "MailTrace AI - packaged runtime check" -ForegroundColor Cyan
Write-Host ("Application folder : {0}" -f $app)
Write-Host ("Runtime folder     : {0}" -f $internal)
Write-Host ""

Add-Type -AssemblyName System.IO.Compression.FileSystem

# 1. executable
$exe = Join-Path $app "MailTrace AI.exe"
$exeOk = (Test-Path $exe) -and ((Get-Item -LiteralPath $exe).Length -gt 5MB)
Check $exeOk "MailTrace AI.exe present" ("{0:N0} bytes" -f @((Get-Item -LiteralPath $exe).Length))

# 2. embedded interpreter
$dll = Join-Path $internal "python312.dll"
$dllOk = (Test-Path $dll) -and ((Get-Item -LiteralPath $dll).Length -gt 1MB)
Check $dllOk "python312.dll (embedded interpreter)" ("{0:N0} bytes" -f @((Get-Item -LiteralPath $dll).Length))

# 3. base library - the file whose absence causes
#    "Failed to start embedded python interpreter!"
$bl = Join-Path $internal "base_library.zip"
$blOk = $false; $blDetail = "missing"
if (Test-Path $bl) {
  $blSize = (Get-Item -LiteralPath $bl).Length
  try {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($bl)
    $names = $zip.Entries | ForEach-Object { $_.FullName }
    $zip.Dispose()
    $core = @("codecs.pyc", "os.pyc", "io.pyc") | Where-Object { $names -contains $_ }
    $blOk = ($names.Count -gt 50) -and ($core.Count -ge 2)
    $blDetail = "{0} modules ({1:N0} bytes) - core present: {2}" -f $names.Count, $blSize, ($core -join ", ")
  } catch {
    $blDetail = "present but not a readable zip: $($_.Exception.Message)"
  }
}
Check $blOk "base_library.zip (Python core modules)" $blDetail

# 4. compiled standard-library extension modules (the lib-dynload set)
$pyd = @(Get-ChildItem -LiteralPath $internal -Filter "*.pyd" -File)
Check ($pyd.Count -ge 10) "compiled extension modules (.pyd)" ("{0} modules: {1}" -f $pyd.Count, (($pyd | Select-Object -First 8 | ForEach-Object { $_.Name }) -join ", "))
$need = @("_socket.pyd", "_ssl.pyd", "select.pyd", "_ctypes.pyd", "unicodedata.pyd")
$haveNeed = @($need | Where-Object { Test-Path (Join-Path $internal $_) })
Check ($haveNeed.Count -eq $need.Count) "required extension modules" ("found {0}/{1}" -f $haveNeed.Count, $need.Count)

# 5. application payload
foreach ($p in @("_internal\backend\main.py",
                "_internal\backend\analyzer\engine.py",
                "_internal\backend\models\phish_nlp_portable.json.gz",
                "_internal\backend\samples",
                "_internal\frontend\index.html",
                "_internal\frontend\vendor\three.min.js")) {
  Check (Test-Path (Join-Path $app $p)) $p
}

Write-Host ""
if ($fail -eq 0) {
  Write-Host "RESULT: the packaged runtime is complete - MailTrace AI can start." -ForegroundColor Green
  Write-Host "        If the window still does not open, run Unblock-Windows.bat first."
  exit 0
} else {
  Write-Host ("RESULT: {0} check(s) FAILED - re-extract the zip (keep the folder structure)." -f $fail) -ForegroundColor Red
  exit 1
}
