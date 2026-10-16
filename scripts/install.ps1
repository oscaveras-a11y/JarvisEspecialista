param([string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & $Python --version
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ is required. Supply -Python with the executable path.' }
    & $Python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
    $venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
    & $venvPython -m pip install -e .
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check network and Python version.' }
    & $venvPython -m cyber_core doctor
    if ($LASTEXITCODE -ne 0) { throw 'Runtime diagnostic failed.' }
    Write-Host 'Installed. Run .\.venv\Scripts\cyber.exe --help'
} finally { Pop-Location }
