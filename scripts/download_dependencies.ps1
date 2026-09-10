$ErrorActionPreference = "Stop"
$Python = if (Test-Path ".venv\Scripts\python.exe") { ".venv\Scripts\python.exe" } else { "python" }
New-Item -ItemType Directory -Force -Path "wheelhouse" | Out-Null
& $Python -m pip install --upgrade pip wheel setuptools
& $Python -m pip download --only-binary=:all: --dest "wheelhouse" -r requirements.txt
& $Python -m pip wheel --no-deps --no-build-isolation --wheel-dir "wheelhouse" .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Get-ChildItem "wheelhouse\*.whl" | Sort-Object Name | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    "$hash  $($_.Name)"
} | Set-Content -Encoding ascii "wheelhouse\MANIFEST.sha256"
Write-Host "Created wheelhouse and wheelhouse\MANIFEST.sha256"
