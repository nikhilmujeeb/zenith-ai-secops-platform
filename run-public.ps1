param(
    [string]$Username,
    [string[]]$AllowedEmail = @()
)

$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot

if (-not $Username) { $Username = Read-Host 'Create a login username' }
if ([string]::IsNullOrWhiteSpace($Username) -or $Username.Contains(':')) {
    throw 'Choose a non-empty username without a colon.'
}

$securePassword = Read-Host 'Create a strong app password (16+ characters)' -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try { $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer) }
if ($password.Length -lt 16) { throw 'The app password must contain at least 16 characters.' }

$cloudflaredPath = Join-Path $projectRoot 'work\cloudflared.exe'
if (-not (Test-Path -LiteralPath $cloudflaredPath)) {
    $cloudflaredCommand = Get-Command cloudflared -ErrorAction SilentlyContinue
    if ($cloudflaredCommand) { $cloudflaredPath = $cloudflaredCommand.Source }
    else { throw 'cloudflared is not installed. Run .\tools\install_cloudflared.ps1 first.' }
}

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
if (-not $pythonPath) { throw 'Python 3.10 or newer is required.' }

$port = if ($env:PORT) { $env:PORT } else { '8000' }
$env:SECOPS_USERNAME = $Username
$env:SECOPS_PASSWORD = $password
$env:SECOPS_PUBLIC = '1'
$env:HOST = '127.0.0.1'
$serverProcess = $null
try {
    $serverProcess = Start-Process -FilePath $pythonPath -ArgumentList @('-u','app/server.py') -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    Remove-Item Env:SECOPS_PASSWORD -ErrorAction SilentlyContinue
    $password = $null
    Start-Sleep -Seconds 2
    if ($serverProcess.HasExited) { throw 'The app server stopped during startup.' }

    $tunnelArgs = @('tunnel','--url',"http://127.0.0.1:$port")
    foreach ($email in $AllowedEmail) {
        if (-not [string]::IsNullOrWhiteSpace($email)) { $tunnelArgs += @('--allowed-mail',$email) }
    }
    Write-Host 'Starting an HTTPS demo tunnel. Keep this window and the computer running.' -ForegroundColor Green
    & $cloudflaredPath @tunnelArgs
    if ($LASTEXITCODE -ne 0) { throw "cloudflared exited with code $LASTEXITCODE." }
}
finally {
    if ($serverProcess -and -not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id -Force }
    Remove-Item Env:SECOPS_USERNAME,Env:SECOPS_PASSWORD,Env:SECOPS_PUBLIC,Env:HOST -ErrorAction SilentlyContinue
}

