<#
.SYNOPSIS
    Blue Team Trainer - Windows Victim VM Setup

.DESCRIPTION
    Prepares a Windows 10/11 VM for use as an Atomic Red Team target.
    Installs and configures:
      - WinRM (HTTP on 5985 - LAB USE ONLY)
      - A dedicated local 'atomicuser' account with admin rights
      - Invoke-AtomicRedTeam PowerShell module + atomics
      - PowerShell script block + module logging
      - Security audit policy (4688 with command line, 4624, 5140)

    Sysmon is intentionally NOT installed - this forces analysts to hunt with
    native Windows event channels (Security, PowerShell/Operational), which
    is more representative of typical enterprise endpoints.

    The Splunk Universal Forwarder is intentionally NOT installed either -
    in this lab, logs reach Splunk only through Velociraptor artifacts that
    analysts explicitly run. This more closely mirrors real DFIR work where
    you target collections deliberately rather than search pre-ingested data.

.PARAMETER AtomicUserPassword
    Password for the local atomic user account.
    MUST match VICTIM_PASS in the backend .env file.

.PARAMETER DisableDefender
    Switch: disable Defender real-time protection (required for many atomics).

.EXAMPLE
    .\victim-setup.ps1 -AtomicUserPassword 'MyStrongP@ss!' -DisableDefender

.PARAMETER AtomicUserPassword
    Password for the local atomic user account.
    MUST match VICTIM_PASS in the backend .env file.

.PARAMETER DisableDefender
    Switch: attempt to disable Defender real-time protection (required for
    many atomics). Will fail silently if Tamper Protection is on - the
    script verifies and prints clear GUI instructions if so.

.EXAMPLE
    .\victim-setup.ps1 -AtomicUserPassword 'MyStrongP@ss!' -DisableDefender

.NOTES
    *** LAB USE ONLY ***
    This script intentionally weakens security posture (disables Defender,
    enables unencrypted WinRM, installs offensive tooling). Only run it on
    an isolated test VM on an isolated network. Never run on production.
    Take a clean VM snapshot before running atomics so you can revert.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$AtomicUserPassword,

    [switch]$DisableDefender
)

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Step($msg) {
    Write-Host "`n==> $msg" -ForegroundColor Cyan
}

function Write-OK($msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "    [!!] $msg" -ForegroundColor Yellow
}

Write-Host @"

  ####################################################
  #                                                  #
  #   Blue Team Trainer - Victim VM Setup          #
  #                                                  #
  #   *** LAB / TRAINING USE ONLY ***                #
  #                                                  #
  ####################################################

"@ -ForegroundColor Magenta

# ---------------------------------------------------------------------------
# 0. Set execution policy
# ---------------------------------------------------------------------------
Write-Step "Setting PowerShell execution policy"
try {
    # LocalMachine = persists across sessions; RemoteSigned = local scripts run,
    # downloaded scripts need a signature. Suitable for a lab.
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Write-OK "Execution policy set to RemoteSigned (LocalMachine)"
} catch {
    Write-Warn "Could not set execution policy: $_"
    Write-Warn "If scripts fail to run, manually set: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine"
}

# ---------------------------------------------------------------------------
# 1. Enable WinRM
# ---------------------------------------------------------------------------
Write-Step "Enabling WinRM (HTTP 5985, basic auth, unencrypted)"
try {
    Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
    Set-Item -Path 'WSMan:\localhost\Service\Auth\Basic' -Value $true
    Set-Item -Path 'WSMan:\localhost\Service\AllowUnencrypted' -Value $true
    Set-Item -Path 'WSMan:\localhost\Client\TrustedHosts' -Value '*' -Force
    if (-not (Get-NetFirewallRule -Name 'WinRM-HTTP-BT' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'WinRM-HTTP-BT' -DisplayName 'WinRM HTTP (BTTrainer)' `
            -Enabled True -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any | Out-Null
    }
    Restart-Service WinRM
    Write-OK "WinRM configured and running"
} catch {
    Write-Warn "WinRM setup issue: $_"
    throw
}

# ---------------------------------------------------------------------------
# 2. Create dedicated local user
# ---------------------------------------------------------------------------
Write-Step "Creating 'atomicuser' local account"
$secure = ConvertTo-SecureString $AtomicUserPassword -AsPlainText -Force
if (Get-LocalUser -Name 'atomicuser' -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name 'atomicuser' -Password $secure
    Write-OK "Password updated on existing atomicuser account"
} else {
    New-LocalUser -Name 'atomicuser' -Password $secure `
        -FullName 'Atomic Test User' -Description 'Used by Blue Team Trainer backend' `
        -PasswordNeverExpires:$true -AccountNeverExpires:$true | Out-Null
    Write-OK "Created atomicuser"
}
Add-LocalGroupMember -Group 'Administrators' -Member 'atomicuser' -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group 'Remote Management Users' -Member 'atomicuser' -ErrorAction SilentlyContinue
Write-OK "atomicuser added to Administrators and Remote Management Users"

# ---------------------------------------------------------------------------
# 3. (Optional) Disable Defender real-time protection
# ---------------------------------------------------------------------------
# Microsoft's Tamper Protection feature blocks programmatic Defender disable.
# When Tamper Protection is on (default on modern Windows), Set-MpPreference
# silently no-ops. There is NO scriptable way to disable Tamper Protection -
# it must be turned off via the Defender GUI by a local admin.
#
# This block tries multiple methods, verifies each one, and surfaces a clear
# warning + GUI instructions when Tamper Protection has won.
if ($DisableDefender) {
    Write-Step "Disabling Defender real-time protection (lab only)"

    # Check Tamper Protection status first - tells us what to expect
    $tamperOn = $false
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $tamperOn = [bool]$status.IsTamperProtected
        Write-Host "    Tamper Protection: $(if ($tamperOn) { 'ON (will block disable attempts)' } else { 'OFF' })" -ForegroundColor $(if ($tamperOn) { 'Yellow' } else { 'Green' })
    } catch {
        Write-Warn "Could not read Defender status: $_"
    }

    # Method 1: Path exclusion. This often works even when Tamper Protection
    # is on, because exclusions are considered safer than disabling protection.
    try {
        Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam' -ErrorAction Stop
        Add-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath "$env:APPDATA" -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess 'powershell.exe' -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess 'cmd.exe' -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess 'wscript.exe' -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess 'mshta.exe' -ErrorAction SilentlyContinue
        Write-OK "Added Defender exclusions for AtomicRedTeam paths and shell processes"
    } catch {
        Write-Warn "Could not add exclusions: $_"
    }

    # Method 2: Disable real-time monitoring features via Set-MpPreference.
    # Each one wrapped individually so partial success isn't lost. Some of
    # these will silently no-op when Tamper Protection is on.
    foreach ($pair in @(
        @{ DisableRealtimeMonitoring = $true },
        @{ DisableBehaviorMonitoring = $true },
        @{ DisableScriptScanning = $true },
        @{ DisableIOAVProtection = $true },
        @{ DisableBlockAtFirstSeen = $true },
        @{ MAPSReporting = 'Disabled' },
        @{ SubmitSamplesConsent = 'NeverSend' }
    )) {
        try { Set-MpPreference @pair -ErrorAction Stop } catch { }
    }

    # Method 3: Group Policy registry keys (works on Pro/Enterprise/Server,
    # not Home edition; Tamper Protection can also block this).
    try {
        $gpoPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        New-Item -Path $gpoPath -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -Path "$gpoPath\Real-Time Protection" -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $gpoPath -Name 'DisableAntiSpyware' -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "$gpoPath\Real-Time Protection" -Name 'DisableRealtimeMonitoring' -Value 1 -Type DWord -ErrorAction SilentlyContinue
    } catch {
        # Ignore - just one of several attempts
    }

    # Verification - what actually stuck?
    Start-Sleep -Seconds 2
    try {
        $final = Get-MpComputerStatus -ErrorAction Stop
        $rtpOff = -not $final.RealTimeProtectionEnabled
        $bmOff  = -not $final.BehaviorMonitorEnabled
        $exclOK = (Get-MpPreference).ExclusionPath -contains 'C:\AtomicRedTeam'

        Write-Host ""
        Write-Host "    Verification:" -ForegroundColor Cyan
        Write-Host "      RealTimeProtection disabled : $(if ($rtpOff) { 'YES' } else { 'NO  <-- STILL ACTIVE' })" -ForegroundColor $(if ($rtpOff) { 'Green' } else { 'Red' })
        Write-Host "      BehaviorMonitoring disabled : $(if ($bmOff)  { 'YES' } else { 'NO' })" -ForegroundColor $(if ($bmOff) { 'Green' } else { 'Red' })
        Write-Host "      AtomicRedTeam excluded      : $(if ($exclOK) { 'YES' } else { 'NO' })" -ForegroundColor $(if ($exclOK) { 'Green' } else { 'Red' })

        if (-not $rtpOff) {
            Write-Host ""
            Write-Host "    !!! DEFENDER REAL-TIME PROTECTION COULD NOT BE DISABLED !!!" -ForegroundColor Red -BackgroundColor Black
            Write-Host ""
            Write-Host "    This is almost certainly Tamper Protection blocking the change." -ForegroundColor Yellow
            Write-Host "    Tamper Protection CANNOT be disabled programmatically by design." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "    Manual fix required (do this on the victim VM, takes 30 seconds):" -ForegroundColor Cyan
            Write-Host "      1. Open Windows Security (search for it in Start menu)" -ForegroundColor White
            Write-Host "      2. Click 'Virus & threat protection'" -ForegroundColor White
            Write-Host "      3. Click 'Manage settings' under 'Virus & threat protection settings'" -ForegroundColor White
            Write-Host "      4. Toggle 'Tamper Protection' to OFF" -ForegroundColor White
            Write-Host "      5. (You may also want to toggle 'Real-time protection' OFF here)" -ForegroundColor White
            Write-Host "      6. Re-run this script with -DisableDefender, OR run:" -ForegroundColor White
            Write-Host "           Set-MpPreference -DisableRealtimeMonitoring `$true" -ForegroundColor White
            Write-Host ""
            Write-Host "    Atomics that drop tools to disk (Mimikatz, Rubeus, ProcDump) WILL FAIL" -ForegroundColor Yellow
            Write-Host "    until this is resolved. Tests that just spawn cmd/powershell may still work." -ForegroundColor Yellow
            Write-Host ""
        } else {
            Write-OK "Defender successfully relaxed"
        }
    } catch {
        Write-Warn "Could not verify Defender state: $_"
    }
}

# ---------------------------------------------------------------------------
# 4. Install Invoke-AtomicRedTeam
# ---------------------------------------------------------------------------
# Following the official Red Canary recommendation, we prefer the PowerShell
# Gallery install method - this places the module in the standard
# AllUsers modules folder ($env:ProgramFiles\WindowsPowerShell\Modules) which
# is already in $env:PSModulePath system-wide, including in WinRM sessions.
#
# Falls back to the script-based installer if the Gallery isn't reachable
# (e.g. fully air-gapped victim with only sneakernet access).
Write-Step "Installing Invoke-AtomicRedTeam (PowerShell Gallery method)"
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'

# Make sure NuGet provider is registered - required for Install-Module.
# This is silent on machines that already have it.
try {
    Get-PackageProvider -Name NuGet -ForceBootstrap -ErrorAction Stop | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
} catch {
    Write-Warn "NuGet provider bootstrap failed: $_ - will try fallback installer"
}

$galleryInstallSucceeded = $false
try {
    # AllUsers scope so the module is discoverable in any PowerShell session
    # on the box, including WinRM-spawned ones. -Force overwrites any old
    # version. powershell-yaml is a hard dependency.
    Install-Module -Name 'invoke-atomicredteam','powershell-yaml' `
        -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
    Write-OK "Installed invoke-atomicredteam + powershell-yaml from PSGallery"
    $galleryInstallSucceeded = $true
} catch {
    Write-Warn "Gallery install failed: $($_.Exception.Message)"
    Write-Warn "Falling back to script-based installer..."
}

# Fallback: if Gallery didn't work, use the legacy IEX-installer approach.
if (-not $galleryInstallSucceeded) {
    try {
        $installer = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing
        Invoke-Expression $installer.Content
        Install-AtomicRedTeam -Force
        Write-OK "Installed Invoke-AtomicRedTeam via fallback script"

        # The script installer drops to C:\AtomicRedTeam\invoke-atomicredteam
        # which ISN'T in PSModulePath. Patch it.
        $found = Get-ChildItem -Path 'C:\AtomicRedTeam' -Filter 'Invoke-AtomicRedTeam.psd1' -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) {
            $moduleDir = $found.Directory.FullName
            $machinePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
            if ($machinePath -notlike "*$moduleDir*") {
                [Environment]::SetEnvironmentVariable('PSModulePath', "$machinePath;$moduleDir", 'Machine')
                $env:PSModulePath = "$env:PSModulePath;$moduleDir"
                Write-OK "Added $moduleDir to system PSModulePath"
            }
        }

        # Also need powershell-yaml when using this method - try Gallery, ignore if it fails
        try {
            Install-Module -Name 'powershell-yaml' -Scope AllUsers -Force -ErrorAction Stop
            Write-OK "Installed powershell-yaml dependency"
        } catch {
            Write-Warn "Could not install powershell-yaml automatically - some atomics may fail to parse"
        }
    } catch {
        Write-Warn "Fallback Atomic install failed: $_"
        throw "Could not install Invoke-AtomicRedTeam by any method"
    }
}

# ---------------------------------------------------------------------------
# Install the atomics folder (test definitions). Done as a separate step
# so it works regardless of which install method ran above.
# ---------------------------------------------------------------------------
Write-Step "Installing the atomics folder (test definitions)"
$atomicsPath = 'C:\AtomicRedTeam\atomics'
if ((Test-Path $atomicsPath) -and ((Get-ChildItem $atomicsPath -Directory -ErrorAction SilentlyContinue).Count -gt 0)) {
    Write-OK "Atomics folder already present at $atomicsPath"
} else {
    try {
        $atomicsInstaller = Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing
        Invoke-Expression $atomicsInstaller.Content
        Install-AtomicsFolder -Force
        Write-OK "Atomics folder installed at $atomicsPath"
    } catch {
        Write-Warn "Atomics folder install failed: $_"
        Write-Warn "Detonations will fail until atomics are present at $atomicsPath"
    }
}

# ---------------------------------------------------------------------------
# Convenience profile (for interactive sessions on the victim)
# ---------------------------------------------------------------------------
$profileSnippet = @'

# Blue Team Trainer - convenience profile (interactive sessions only)
$PSDefaultParameterValues = @{'Invoke-AtomicTest:PathToAtomicsFolder'='C:\AtomicRedTeam\atomics'}
'@
$allUsersProfile = "$PSHome\Profile.ps1"
if (-not (Test-Path $allUsersProfile)) {
    New-Item -Path $allUsersProfile -ItemType File -Force | Out-Null
}
if (-not ((Get-Content $allUsersProfile -Raw -ErrorAction SilentlyContinue) -match 'PathToAtomicsFolder')) {
    Add-Content -Path $allUsersProfile -Value $profileSnippet
    Write-OK "Convenience profile updated ($allUsersProfile)"
}

# ---------------------------------------------------------------------------
# Verify the module loads from a clean PowerShell session - this mirrors
# what WinRM-spawned sessions will see. If this fails, the platform won't work.
# ---------------------------------------------------------------------------
Write-Step "Verifying module loads from a clean PowerShell session"
$verifyResult = & powershell.exe -NoProfile -NonInteractive -Command @"
`$ErrorActionPreference = 'Stop'
try {
    `$m = Get-Module -ListAvailable Invoke-AtomicRedTeam | Select-Object -First 1
    if (-not `$m) { 'NOT_FOUND'; exit 1 }
    Import-Module `$m.Name -Force
    if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
        'LOADED ' + `$m.Path
    } else {
        'CMD_NOT_AVAILABLE'; exit 1
    }
} catch {
    "ERROR `$(`$_.Exception.Message)"; exit 1
}
"@ 2>&1

if ($LASTEXITCODE -eq 0 -and "$verifyResult" -match '^LOADED ') {
    Write-OK "Module loads cleanly: $verifyResult"
} else {
    Write-Warn "Module verification failed: $verifyResult"
    Write-Warn "Try rebooting the victim VM so PSModulePath changes take effect everywhere."
    Write-Warn "After reboot, test with: powershell.exe -NoProfile -Command 'Get-Module -ListAvailable Invoke-AtomicRedTeam'"
}

# ---------------------------------------------------------------------------
# 5. Enable PowerShell script block + module logging
# ---------------------------------------------------------------------------
Write-Step "Enabling PowerShell script block & module logging"
$psLogRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$psLogRoot\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLogRoot\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord
New-Item -Path "$psLogRoot\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "$psLogRoot\ModuleLogging" -Name 'EnableModuleLogging' -Value 1 -Type DWord
New-Item -Path "$psLogRoot\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$psLogRoot\ModuleLogging\ModuleNames" -Name '*' -Value '*'
Write-OK "PowerShell auditing enabled"

# ---------------------------------------------------------------------------
# 6. Enable Security event audit policy (Process Creation with command line)
# ---------------------------------------------------------------------------
Write-Step "Enabling detailed process tracking with command line"
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
Write-OK "Command line auditing enabled for 4688 events"

# ---------------------------------------------------------------------------
# 7. Create Atomic log directory
# ---------------------------------------------------------------------------
New-Item -Path 'C:\AtomicRedTeam\logs' -ItemType Directory -Force | Out-Null

# ---------------------------------------------------------------------------
# 8. Velociraptor agent reminder
# ---------------------------------------------------------------------------
# This setup deliberately does NOT install a Splunk Universal Forwarder.
# Logs reach Splunk only through Velociraptor artifacts that an analyst
# explicitly runs - this is closer to real DFIR work where you target
# collections deliberately rather than searching pre-ingested data.
#
# The Velociraptor agent itself must be deployed manually (the Velociraptor
# server generates an MSI per environment, and we don't want to bake your
# server's URL/cert into this script). See setup/velociraptor-agent-deploy.md
# in this repo for the agent install steps.
Write-Step "Velociraptor agent (manual step)"
Write-Host "    The Velociraptor agent is NOT installed by this script." -ForegroundColor Yellow
Write-Host "    Generate an MSI for your Velociraptor server (Server Artifacts ->" -ForegroundColor Yellow
Write-Host "    Server.Utils.CreateMSI), then deploy it to this victim manually." -ForegroundColor Yellow
Write-Host "    Without it, the platform's Velociraptor->Splunk pipeline cannot work." -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

# Discover a sensible-looking IPv4 address for the final message.
# Excludes loopback (127.x), APIPA (169.254.x), and Hyper-V default-switch (172.x).
$victimIP = try {
    $candidates = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {
            $_.IPAddress -notmatch '^(127\.|169\.254\.|172\.)' -and
            $_.PrefixOrigin -ne 'WellKnown'
        } |
        Select-Object -ExpandProperty IPAddress
    if ($candidates) { $candidates[0] } else { '<unable to detect - run ipconfig>' }
} catch {
    '<unable to detect - run ipconfig>'
}

Write-Host @"

  ####################################################
  #                                                  #
  #   SETUP COMPLETE                                 #
  #                                                  #
  ####################################################

  Detected victim IP: $victimIP

  Next steps:
    1. Take a VM snapshot NOW (pre-detonation baseline)
    2. From your analyst workstation, configure the backend .env:
         VICTIM_HOST = $victimIP
         VICTIM_USER = atomicuser
         VICTIM_PASS = <the password you just set>
    3. Start the backend: uvicorn main:app --host 0.0.0.0 --port 8000
    4. Open the frontend, flip to Live Mode, and start detonating

  NOTE: Sysmon is NOT installed. Analysts will hunt with native Windows
  event channels (Security 4688, PowerShell/Operational 4104, etc.) -
  more representative of typical enterprise endpoints.

  Remember: revert this VM to the snapshot regularly to keep a clean baseline.

"@ -ForegroundColor Green
