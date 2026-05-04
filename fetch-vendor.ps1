<#
.SYNOPSIS
    Download React + Babel UMD bundles for offline use of blueteam-trainer.html

.DESCRIPTION
    Run this ONCE on any machine with internet access (your build laptop, NOT
    the air-gapped victim/analyst boxes). It populates a ./vendor folder
    next to the HTML file with the three JS files needed to render the app.

    After running this, you can copy the entire blueteam-trainer folder
    onto an air-gapped laptop and the HTML file will work offline.

.EXAMPLE
    .\fetch-vendor.ps1

.NOTES
    Files downloaded (~700KB total):
      - react.production.min.js
      - react-dom.production.min.js
      - babel.min.js
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vendorDir = Join-Path $scriptDir 'vendor'
New-Item -Path $vendorDir -ItemType Directory -Force | Out-Null

$files = @(
    @{ Name = 'react.production.min.js'
       Url  = 'https://unpkg.com/react@18.3.1/umd/react.production.min.js' }
    @{ Name = 'react-dom.production.min.js'
       Url  = 'https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js' }
    @{ Name = 'babel.min.js'
       Url  = 'https://unpkg.com/@babel/standalone@7.25.6/babel.min.js' }
)

Write-Host "`nFetching vendor libraries to $vendorDir`n" -ForegroundColor Cyan

foreach ($f in $files) {
    $dest = Join-Path $vendorDir $f.Name
    if (Test-Path $dest) {
        Write-Host "  [SKIP] $($f.Name) already present" -ForegroundColor DarkGray
        continue
    }
    Write-Host "  [GET ] $($f.Name)" -ForegroundColor Yellow -NoNewline
    try {
        Invoke-WebRequest -Uri $f.Url -OutFile $dest -UseBasicParsing
        $size = (Get-Item $dest).Length
        Write-Host "  ($([math]::Round($size/1KB,1)) KB)" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED: $_" -ForegroundColor Red
        throw
    }
}

Write-Host "`nDone. You can now open blueteam-trainer.html in any browser." -ForegroundColor Green
Write-Host "To use on an air-gapped machine, copy the entire folder (including ./vendor)." -ForegroundColor Green
