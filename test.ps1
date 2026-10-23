$ErrorActionPreference = 'Stop'

$pythonPath = $null
$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCommand) {
    try {
        & $pythonCommand.Source --version *> $null
        if ($LASTEXITCODE -eq 0) { $pythonPath = $pythonCommand.Source }
    } catch { $pythonPath = $null }
}

if (-not $pythonPath) {
    $bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    if (Test-Path -LiteralPath $bundledPython) { $pythonPath = $bundledPython }
}

if (-not $pythonPath) {
    throw 'Python 3.10 or newer is required. Install Python or add it to PATH, then run this script again.'
}

& $pythonPath -m unittest discover -s tests -v
exit $LASTEXITCODE

