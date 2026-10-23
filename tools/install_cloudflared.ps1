$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$workDir = Join-Path $projectRoot 'work'
$exePath = Join-Path $workDir 'cloudflared.exe'
$apiHeaders = @{ 'User-Agent' = 'Zenith-SecOps-demo-installer' }
$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/cloudflare/cloudflared/releases/latest' -Headers $apiHeaders
$asset = $release.assets | Where-Object { $_.name -eq 'cloudflared-windows-amd64.exe' } | Select-Object -First 1
if (-not $asset) { throw 'The official Cloudflare release did not include the Windows x64 executable.' }
if (-not $asset.digest -or $asset.digest -notmatch '^sha256:([0-9a-fA-F]{64})$') {
    throw 'The official release did not publish a SHA-256 asset digest; refusing an unverified download.'
}
$expectedDigest = $Matches[1].ToLowerInvariant()

New-Item -ItemType Directory -Path $workDir -Force | Out-Null
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $exePath
$actualDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $exePath).Hash.ToLowerInvariant()
if ($actualDigest -ne $expectedDigest) {
    Remove-Item -LiteralPath $exePath -Force
    throw 'The downloaded cloudflared executable did not match the official release digest.'
}
& $exePath --version
if ($LASTEXITCODE -ne 0) { throw 'cloudflared could not be launched.' }
Write-Host "Verified official Cloudflare binary saved to $exePath"

