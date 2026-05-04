<#
.SYNOPSIS
    Quick-fix for victims where Invoke-AtomicRedTeam is installed but
    not loadable in WinRM sessions.

.DESCRIPTION
    Run this on the victim VM if you ran the OLD victim-setup.ps1 and are now
    getting "module Invoke-AtomicRedTeam was not loaded" errors from the
    backend. It will:

      1. Set execution policy to RemoteSigned (LocalMachine)
      2. Bootstrap NuGet provider for PowerShell Gallery access
      3. Install invoke-atomicredteam + powershell-yaml from the Gallery
         (these go into the AllUsers modules folder which is in PSModulePath)
      4. Verify the module loads in a clean PowerShell session
      5. Restart WinRM so it picks up the new module path

    After this script completes, your detonations from the platform should
    succeed.

.EXAMPLE
    # On the victim, in elevated PowerShell:
    .\fix-atomic-install.ps1
#>
[CmdletBinding()]
param()

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

function W($m, $c='Cyan')  { Write-Host "==> $m" -ForegroundColor $c }
function OK($m) { Write-Host "    [OK] $m" -ForegroundColor Green }
function WN($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

W "Setting execution policy"
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
OK "RemoteSigned applied"

W "Bootstrapping NuGet provider"
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
try {
    Get-PackageProvider -Name NuGet -ForceBootstrap -ErrorAction Stop | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    OK "NuGet ready"
} catch {
    WN "NuGet bootstrap had an issue: $_"
}

W "Installing invoke-atomicredteam + powershell-yaml from PSGallery (AllUsers)"
try {
    Install-Module -Name 'invoke-atomicredteam','powershell-yaml' `
        -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
    OK "Modules installed"
} catch {
    WN "Gallery install failed: $($_.Exception.Message)"
    WN "If this is an air-gapped victim, you'll need to use Save-Module on a"
    WN "machine with internet, copy the modules to this victim, and place them"
    WN "under C:\Program Files\WindowsPowerShell\Modules\."
    throw
}

W "Ensuring atomics folder is present"
if ((Test-Path 'C:\AtomicRedTeam\atomics') -and `
    ((Get-ChildItem 'C:\AtomicRedTeam\atomics' -Directory -EA SilentlyContinue).Count -gt 0)) {
    OK "Atomics already present at C:\AtomicRedTeam\atomics"
} else {
    try {
        $installer = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing
        Invoke-Expression $installer.Content
        Install-AtomicsFolder -Force
        OK "Atomics folder installed"
    } catch {
        WN "Atomics folder install failed: $_"
    }
}

W "Verifying module loads from a clean PowerShell session"
$result = & powershell.exe -NoProfile -NonInteractive -Command @"
`$ErrorActionPreference = 'Stop'
try {
    `$m = Get-Module -ListAvailable Invoke-AtomicRedTeam | Select-Object -First 1
    if (-not `$m) { 'NOT_FOUND'; exit 1 }
    Import-Module `$m.Name -Force
    if (Get-Command Invoke-AtomicTest -EA SilentlyContinue) { 'LOADED ' + `$m.Path }
    else { 'CMD_NOT_AVAILABLE'; exit 1 }
} catch {
    "ERROR `$(`$_.Exception.Message)"; exit 1
}
"@ 2>&1

if ($LASTEXITCODE -eq 0 -and "$result" -match '^LOADED ') {
    OK "$result"
} else {
    WN "Verification failed: $result"
    WN "Try rebooting the victim VM and run this script again."
    exit 1
}

W "Restarting WinRM to pick up new module path"
try {
    Restart-Service WinRM -Force
    OK "WinRM restarted"
} catch {
    WN "Could not restart WinRM: $_"
}

Write-Host ""
Write-Host "  ====================================================" -ForegroundColor Green
Write-Host "  FIX COMPLETE" -ForegroundColor Green
Write-Host "  ====================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Now from the Ubuntu backend:" -ForegroundColor Cyan
Write-Host "    cd ~/blueteam-trainer/backend"
Write-Host "    source .venv/bin/activate"
Write-Host "    python diagnose.py"
Write-Host ""
Write-Host "  All 6 checks should now pass." -ForegroundColor Cyan
Write-Host ""
