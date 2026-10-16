param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$previousPath = $env:PYTHONPATH
Push-Location $projectRoot
try {
    $env:PYTHONPATH = Join-Path $projectRoot 'src'
    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Automated tests failed.' }
    & $Python scripts/demo.py
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic integration demonstration failed.' }
} finally {
    $env:PYTHONPATH = $previousPath
    Pop-Location
}
