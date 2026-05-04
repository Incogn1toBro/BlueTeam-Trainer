<#
.SYNOPSIS
    Serve blueteam-trainer.html on http://localhost:8080

.DESCRIPTION
    Some browsers (notably Chrome) refuse to load local <script src=...> tags
    when the parent HTML is opened via file://. This launcher starts a tiny
    Python HTTP server in the current folder so the page loads cleanly via
    http://localhost:8080.

    Requires Python 3 to be installed and on PATH.

    Press Ctrl+C in the terminal window to stop the server.

.EXAMPLE
    .\start-trainer.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 8080
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Verify Python
$pythonCmd = $null
foreach ($cmd in 'python', 'python3', 'py') {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $pythonCmd = $cmd
        break
    }
}
if (-not $pythonCmd) {
    Write-Host "Python not found on PATH." -ForegroundColor Red
    Write-Host "Install Python 3 from https://www.python.org/downloads/ and re-run." -ForegroundColor Yellow
    exit 1
}

# Verify vendor folder
if (-not (Test-Path "$scriptDir\vendor\react.production.min.js")) {
    Write-Host "Vendor libraries missing." -ForegroundColor Red
    Write-Host "Run .\fetch-vendor.ps1 first (needs internet, one time only)." -ForegroundColor Yellow
    exit 1
}

$url = "http://localhost:$Port/blueteam-trainer.html"

Write-Host @"

  ####################################################
  #                                                  #
  #   Blue Team Trainer - Local Server             #
  #                                                  #
  ####################################################

  Serving on:  $url
  From:        $scriptDir

  Opening browser in 2 seconds...
  Press Ctrl+C to stop the server.

"@ -ForegroundColor Cyan

Start-Job -ScriptBlock {
    param($u)
    Start-Sleep -Seconds 2
    Start-Process $u
} -ArgumentList $url | Out-Null

& $pythonCmd -m http.server $Port --bind 127.0.0.1
