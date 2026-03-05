$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

Get-ChildItem -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse -File -Include *.pyc,*.pyo | Remove-Item -Force -ErrorAction SilentlyContinue

if (Test-Path 'reconhive.egg-info') { Remove-Item -Recurse -Force 'reconhive.egg-info' }
if (Test-Path 'recon_runs') { Remove-Item -Recurse -Force 'recon_runs' }

$archiveDir = Join-Path $root 'release'
if (-not (Test-Path $archiveDir)) { New-Item -Path $archiveDir -ItemType Directory | Out-Null }

$archivePath = Join-Path $archiveDir 'ReconHive.zip'
if (Test-Path $archivePath) { Remove-Item -Force $archivePath }

$items = Get-ChildItem -Force | Where-Object {
    $_.Name -notin @('.git', '.venv', 'venv', 'release', 'certinia')
}

Compress-Archive -Path $items.FullName -DestinationPath $archivePath -Force
Write-Host "Created clean archive: $archivePath"
