import React, { useState, useCallback, useRef } from "react";

const C = {
  bg: '#0d1117', surface: '#161b22', elevated: '#1c2128', border: '#21262d',
  accent: '#00d97e', accentDim: 'rgba(0,217,126,0.12)', accentText: '#00b865',
  text: '#e6edf3', textSec: '#8b949e', textMuted: '#3d444d',
  red: '#f85149', amber: '#d29922', blue: '#388bfd', purple: '#a371f7',
  orange: '#f0883e', pink: '#f778ba', teal: '#56d4c8', yellow: '#e3b341',
};

const TACTIC_META = {
  'TA0001': { name: 'Initial Access', color: '#f85149' },
  'TA0002': { name: 'Execution', color: '#f0883e' },
  'TA0003': { name: 'Persistence', color: '#d29922' },
  'TA0004': { name: 'Privilege Escalation', color: '#7ee787' },
  'TA0005': { name: 'Defense Evasion', color: '#388bfd' },
  'TA0006': { name: 'Credential Access', color: '#a371f7' },
  'TA0007': { name: 'Discovery', color: '#79c0ff' },
  'TA0008': { name: 'Lateral Movement', color: '#f778ba' },
  'TA0009': { name: 'Collection', color: '#56d4c8' },
  'TA0011': { name: 'Command & Control', color: '#ff7b72' },
  'TA0010': { name: 'Exfiltration', color: '#bd93f9' },
  'TA0040': { name: 'Impact', color: '#ff5555' },
};

const TECHNIQUES = [
  {
    id: 'T1566.001', tactic: 'TA0002', name: 'Spearphishing Attachment', offlineCapable: false, prereqStage: false,
    description: 'Adversaries send emails with malicious attachments (macros, exploits) to gain execution on victim hosts. Office documents with VBA macros are most common.',
    atomicTests: [
      { id: 'T1566.001-1', name: 'Malicious Macro via Office Document', description: 'Creates and opens a macro-enabled .docm that spawns cmd.exe, simulating initial execution from a phishing document.' },
      { id: 'T1566.001-2', name: 'Download Payload via Embedded URL', description: 'Office document containing a URL that downloads a remote payload using URLDownloadToFile.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1\n  Image="*\\\\WINWORD.EXE" OR Image="*\\\\EXCEL.EXE"\n| where match(CommandLine, "(?i)(cmd|powershell|wscript|cscript)")\n| table _time, Computer, User, Image, CommandLine`,
        `index=sysmon EventCode=1\n  ParentImage IN ("*\\\\WINWORD.EXE","*\\\\EXCEL.EXE","*\\\\OUTLOOK.EXE")\n  Image IN ("*\\\\cmd.exe","*\\\\powershell.exe","*\\\\wscript.exe","*\\\\mshta.exe")\n| table _time, Computer, User, ParentImage, Image, CommandLine`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(\n  EvtxGlob="**\\\\*.evtx", IdRegex="4688")\nWHERE NewProcessName =~ "(?i)(WINWORD|EXCEL|OUTLOOK).EXE"`,
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE ParentName =~ "(?i)(WINWORD|EXCEL|OUTLOOK).EXE"\n  AND Name =~ "(?i)(cmd|powershell|wscript|cscript).exe"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |\n  Where-Object { $_.Message -match 'WINWORD.EXE|EXCEL.EXE' -and\n    $_.Message -match 'powershell|cmd|wscript' } |\n  Select-Object TimeCreated, Message | Format-List`,
        `Get-ChildItem "$env:APPDATA\\Microsoft\\Office\\Recent\\" |\n  Sort-Object LastWriteTime -Descending |\n  Select-Object -First 20 FullName, LastWriteTime`,
      ]
    }
  },
  {
    id: 'T1059.001', tactic: 'TA0002', name: 'PowerShell Execution', offlineCapable: false, prereqStage: true,
    description: 'Adversaries abuse PowerShell for execution using encoded commands, download cradles, and AMSI bypass techniques to evade detection.',
    atomicTests: [
      { id: 'T1059.001-1', name: 'Encoded PowerShell Command', description: 'Executes a base64-encoded payload via powershell.exe -EncodedCommand, a common evasion technique.' },
      { id: 'T1059.001-2', name: 'Download Cradle (IEX + WebClient)', description: 'Uses Invoke-Expression with Net.WebClient.DownloadString to pull and execute remote code in memory.' },
      { id: 'T1059.001-3', name: 'AMSI Bypass via Reflection', description: 'Patches the AmsiScanBuffer function in memory to disable AMSI scanning before running malicious scripts.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1 Image="*\\\\powershell.exe"\n| eval encoded=if(match(CommandLine,"(?i)-e(nc(odedcommand)?)? "),"YES","NO")\n| table _time, Computer, User, CommandLine, encoded\n| sort - encoded`,
        `index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104\n  Message IN ("*Invoke-Expression*","*DownloadString*","*EncodedCommand*","*AmsiScanBuffer*")\n| rex field=Message "ScriptBlock text = (?P<script>.+?)\\n"\n| table _time, Computer, User, script`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.EventLogs.PowerShell.ScriptBlock()\nWHERE Script =~ "(?i)(invoke-expression|iex|downloadstring|encodedcommand|amsiscan|reflection.assembly)"`,
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE Name =~ "powershell.exe"\n  AND CommandLine =~ "(?i)(-enc|-e |encodedcommand|-nop|-noni|bypass)"`,
      ],
      powershell: [
        `Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |\n  Where-Object { $_.Id -eq 4104 -and\n    $_.Message -match 'EncodedCommand|DownloadString|Invoke-Expression|AmsiScan' } |\n  Select-Object TimeCreated, @{N='Script';E={$_.Message -replace '.*ScriptBlock text = ',''\n    -replace '\\n.*',''}} | Format-List`,
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |\n  Where-Object {$_.Message -match 'powershell.exe.{0,100}-e'} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1059.003', tactic: 'TA0002', name: 'Windows Command Shell', offlineCapable: true, prereqStage: false,
    description: 'Adversaries abuse cmd.exe for execution of commands and batch scripts, often spawned from Office applications or other unusual parent processes.',
    atomicTests: [
      { id: 'T1059.003-1', name: 'Suspicious CMD Spawned from Office', description: 'Launches cmd.exe as a child of WINWORD.EXE, simulating macro-initiated command execution.' },
      { id: 'T1059.003-2', name: 'Batch Script Execution', description: 'Creates and executes a .bat file containing enumeration and staging commands.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1\n  ParentImage IN ("*\\\\winword.exe","*\\\\excel.exe","*\\\\outlook.exe")\n  Image="*\\\\cmd.exe"\n| table _time, Computer, User, ParentImage, CommandLine`,
        `index=sysmon EventCode=1 Image="*\\\\cmd.exe"\n| stats count by Computer, User, ParentImage\n| where count > 10\n| sort - count`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE Name =~ "cmd.exe"\n  AND ParentName =~ "(?i)(WINWORD|EXCEL|OUTLOOK|mshta|wscript).exe"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |\n  Where-Object {$_.Message -match 'cmd.exe' -and\n    $_.Message -match 'WINWORD.EXE|EXCEL.EXE|OUTLOOK.EXE'} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1547.001', tactic: 'TA0003', name: 'Registry Run Keys', offlineCapable: true, prereqStage: false,
    description: 'Adversaries establish persistence by writing to Run/RunOnce registry keys or dropping files into Startup folders, ensuring execution on each logon.',
    atomicTests: [
      { id: 'T1547.001-1', name: 'HKCU Run Key Persistence', description: 'Writes a payload path to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.' },
      { id: 'T1547.001-2', name: 'HKLM Run Key Persistence', description: 'Writes to HKLM Run key, requiring elevated privileges, persisting for all users.' },
      { id: 'T1547.001-3', name: 'User Startup Folder Drop', description: 'Drops a .bat or .lnk file into the current user\'s Startup folder.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=13\n  TargetObject IN ("*\\\\CurrentVersion\\\\Run\\\\*","*\\\\CurrentVersion\\\\RunOnce\\\\*")\n| table _time, Computer, User, TargetObject, Details, Image`,
        `index=sysmon EventCode=11\n  TargetFilename="*\\\\Start Menu\\\\Programs\\\\Startup\\\\*"\n| table _time, Computer, User, TargetFilename, Image`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Sys.StartupItems()`,
        `SELECT * FROM Artifact.Windows.Registry.NTUser(\n  KeyGlob="SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run**")`,
      ],
      powershell: [
        `Get-ItemProperty "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | Format-List\nGet-ItemProperty "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" | Format-List`,
        `Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" |\n  Select-Object FullName, LastWriteTime, Length`,
      ]
    }
  },
  {
    id: 'T1053.005', tactic: 'TA0003', name: 'Scheduled Tasks', offlineCapable: true, prereqStage: false,
    description: 'Adversaries use schtasks.exe or the Task Scheduler API to run payloads on a schedule, at system startup, or on specific triggers.',
    atomicTests: [
      { id: 'T1053.005-1', name: 'Scheduled Task at Startup', description: 'Creates a task via schtasks.exe to run a payload at SYSTEM boot.' },
      { id: 'T1053.005-2', name: 'Scheduled Task on Logon', description: 'Registers a scheduled task triggered on user logon using an XML task definition.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1 Image="*\\\\schtasks.exe" CommandLine="*/create*"\n| table _time, Computer, User, CommandLine`,
        `index=wineventlog EventCode IN (4698, 4702)\n| rex field=Message "Task Name:\\\\s+(?P<task>[^\\\\n]+)"\n| table _time, ComputerName, EventCode, task, Message`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.System.ScheduledTasks()\nWHERE Enabled = "true"\n  AND (Command =~ "(?i)(powershell|cmd|wscript|mshta|rundll32)"\n    OR WorkingDirectory =~ "(?i)(temp|appdata|public)")`,
      ],
      powershell: [
        `Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |\n  Select-Object TaskName, TaskPath, State,\n    @{N='Execute';E={$_.Actions.Execute}},\n    @{N='Trigger';E={$_.Triggers.CimClass.CimClassName}} |\n  Format-List`,
        `Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' |\n  Where-Object {$_.Id -in @(106,129,200)} |\n  Select-Object TimeCreated, Id, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1543.003', tactic: 'TA0003', name: 'Windows Service Creation', offlineCapable: true, prereqStage: false,
    description: 'Adversaries create or modify Windows services to execute malicious payloads and maintain persistence, often with SYSTEM-level privileges.',
    atomicTests: [
      { id: 'T1543.003-1', name: 'Service Creation via sc.exe', description: 'Uses sc.exe to create a new service pointing to a malicious binary.' },
      { id: 'T1543.003-2', name: 'Service Binary Hijack', description: 'Replaces a legitimate service binary path with a malicious executable.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1 Image="*\\\\sc.exe" CommandLine="*create*"\n| table _time, Computer, User, CommandLine`,
        `index=wineventlog EventCode=7045\n| table _time, ComputerName, Message\n| rex field=Message "Service Name:\\\\s+(?P<svc>[^\\\\n]+)"\n| rex field=Message "Service File Name:\\\\s+(?P<path>[^\\\\n]+)"`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.System.Services()\nWHERE StartMode = "auto"\n  AND (PathName =~ "(?i)(temp|appdata|users\\\\public)"\n    OR NOT PathName =~ "(?i)(windows|program files)")`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |\n  Select-Object TimeCreated, Message | Format-List`,
        `Get-Service | Where-Object {$_.Status -eq 'Running'} |\n  ForEach-Object { $svc = $_\n    $bin = (Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'").PathName\n    [PSCustomObject]@{Name=$svc.Name; Binary=$bin} } |\n  Where-Object {$_.Binary -match 'temp|appdata|public'} | Format-List`,
      ]
    }
  },
  {
    id: 'T1548.002', tactic: 'TA0004', name: 'Bypass UAC', offlineCapable: true, prereqStage: false,
    description: 'Adversaries bypass UAC to elevate processes without triggering the consent dialog, using trusted Windows binaries that auto-elevate and can be hijacked.',
    atomicTests: [
      { id: 'T1548.002-1', name: 'UAC Bypass via eventvwr.exe', description: 'Hijacks the registry key used by eventvwr.exe to spawn an elevated process without a UAC prompt.' },
      { id: 'T1548.002-2', name: 'UAC Bypass via fodhelper.exe', description: 'Abuses fodhelper.exe\'s auto-elevation and ms-settings handler to execute a payload as high integrity.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=13\n  TargetObject IN ("*\\\\ms-settings\\\\shell\\\\open\\\\command*","*\\\\mscfile\\\\shell\\\\open\\\\command*")\n| table _time, Computer, User, Image, TargetObject, Details`,
        `index=sysmon EventCode=1\n  Image IN ("*\\\\eventvwr.exe","*\\\\fodhelper.exe")\n  IntegrityLevel="High"\n| table _time, Computer, User, Image, ParentImage, CommandLine`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Registry.NTUser(\n  KeyGlob="SOFTWARE\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command**")`,
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE Name =~ "(?i)(eventvwr|fodhelper|sdclt|cmstp).exe"`,
      ],
      powershell: [
        `Get-ItemProperty "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" -EA SilentlyContinue | Format-List\nGet-ItemProperty "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" -EA SilentlyContinue | Format-List`,
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |\n  Where-Object {$_.Message -match '(eventvwr|fodhelper|sdclt).exe'} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1070.001', tactic: 'TA0005', name: 'Clear Windows Event Logs', offlineCapable: true, prereqStage: false,
    description: 'Adversaries clear Windows Event Logs to remove evidence of their activity, often targeting the Security, System, and Application channels.',
    atomicTests: [
      { id: 'T1070.001-1', name: 'Clear Logs via wevtutil', description: 'Runs wevtutil.exe cl Security/System/Application to clear event log channels.' },
      { id: 'T1070.001-2', name: 'Clear Logs via PowerShell', description: 'Uses Clear-EventLog and Clear-WinEvent cmdlets to wipe log channels programmatically.' },
    ],
    huntPack: {
      splunk: [
        `index=wineventlog EventCode=1102 OR EventCode=104\n| table _time, ComputerName, EventCode, Message`,
        `index=sysmon EventCode=1\n  Image="*\\\\wevtutil.exe" CommandLine IN ("*cl *","*clear-log*")\n| table _time, Computer, User, CommandLine`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(\n  EvtxGlob="**\\\\Security.evtx", IdRegex="1102")`,
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE CommandLine =~ "(?i)wevtutil.*(cl |clear-log)"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |\n  Select-Object TimeCreated, Message | Format-List`,
        `Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1055.001', tactic: 'TA0005', name: 'Process Injection (DLL)', offlineCapable: false, prereqStage: true,
    description: 'Adversaries inject malicious DLLs into legitimate processes to execute code under their context, evade detection, and bypass process-based defences.',
    atomicTests: [
      { id: 'T1055.001-1', name: 'DLL Injection via mavinject.exe', description: 'Uses the built-in mavinject.exe utility to inject a DLL into a target process by PID.' },
      { id: 'T1055.001-2', name: 'Reflective DLL Injection', description: 'Injects a DLL into a remote process using CreateRemoteThread + LoadLibrary without writing to disk.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=8\n| table _time, Computer, SourceImage, TargetImage, StartAddress, StartFunction`,
        `index=sysmon EventCode=1 Image="*\\\\mavinject.exe"\n| table _time, Computer, User, CommandLine`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Memory.InjectedThreads()`,
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE CommandLine =~ "(?i)mavinject"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=8} |\n  Select-Object TimeCreated, Message | Format-List`,
        `Get-Process | ForEach-Object {\n  $p = $_\n  try { $p.Modules |\n    Where-Object {$_.FileName -notmatch '(?i)(system32|syswow64|program files)'} |\n    Select-Object @{N='Process';E={$p.Name}},@{N='PID';E={$p.Id}},FileName\n  } catch {}\n} | Format-List`,
      ]
    }
  },
  {
    id: 'T1003.001', tactic: 'TA0006', name: 'LSASS Memory Dump', offlineCapable: false, prereqStage: true,
    description: 'Adversaries access LSASS process memory to extract credentials including NTLM hashes and Kerberos tickets. One of the most common post-exploitation techniques.',
    atomicTests: [
      { id: 'T1003.001-1', name: 'LSASS Dump via ProcDump', description: 'Uses Sysinternals procdump64.exe with -ma flag to create a full LSASS minidump.' },
      { id: 'T1003.001-2', name: 'LSASS Dump via comsvcs.dll MiniDump', description: 'Calls MiniDump export via rundll32.exe comsvcs.dll — a LOLBin technique requiring no external tools.' },
      { id: 'T1003.001-3', name: 'Mimikatz sekurlsa::logonpasswords', description: 'Executes Mimikatz to read credentials directly from LSASS memory.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"\n  GrantedAccess IN ("0x1010","0x1038","0x1410","0x40","0x1FFFFF")\n| table _time, Computer, SourceImage, TargetImage, GrantedAccess, User`,
        `index=sysmon EventCode=1\n  Image IN ("*\\\\procdump.exe","*\\\\procdump64.exe") CommandLine="*lsass*"\n| table _time, Computer, User, CommandLine`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Memory.ProcessHandles(\n  ProcessRegex="lsass")\nWHERE GrantedAccess =~ "(0x1010|0x1038|0x1410|0x1FFFFF)"`,
        `SELECT * FROM Artifact.Windows.Detection.Yara.Process(\n  ProcessRegex="lsass",\n  YaraRule="rule mimikatz { strings: $a = \"mimikatz\" nocase condition: $a }")`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |\n  Where-Object {$_.Message -match 'lsass.exe'} |\n  Select-Object TimeCreated, Message | Format-List`,
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4656} |\n  Where-Object {$_.Message -match 'lsass.exe'} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1558.003', tactic: 'TA0006', name: 'Kerberoasting', offlineCapable: false, prereqStage: true,
    description: 'Adversaries request service tickets for accounts with SPNs, then crack the tickets offline to recover plaintext service account passwords.',
    atomicTests: [
      { id: 'T1558.003-1', name: 'Kerberoasting via Rubeus', description: 'Uses Rubeus.exe kerberoast to request RC4 TGS tickets for all kerberoastable accounts.' },
      { id: 'T1558.003-2', name: 'Kerberoasting via PowerView', description: 'Uses Invoke-Kerberoast from PowerSploit to request and export kerberoastable hashes.' },
    ],
    huntPack: {
      splunk: [
        `index=wineventlog EventCode=4769\n  TicketEncryptionType="0x17" TicketOptions="0x40810000"\n| stats count by TargetUserName, ServiceName, ClientAddress\n| sort - count`,
        `index=wineventlog EventCode=4769 TicketEncryptionType="0x17"\n| where ServiceName!="krbtgt" AND NOT ServiceName="*$"\n| table _time, ComputerName, TargetUserName, ServiceName, ClientAddress`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(\n  EvtxGlob="**\\\\Security.evtx", IdRegex="4769")\nWHERE TicketEncryptionType = "0x17"\n  AND NOT ServiceName =~ "(krbtgt|\\\\$)"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |\n  Where-Object {$_.Message -match 'Ticket Encryption Type:\\s+0x17'} |\n  Select-Object TimeCreated, Message | Format-List`,
        `# Identify kerberoastable accounts (run on DC)\nGet-ADUser -Filter {ServicePrincipalName -ne "$null" -and Enabled -eq $true} |\n  Select-Object Name, SamAccountName, ServicePrincipalName | Format-Table`,
      ]
    }
  },
  {
    id: 'T1082', tactic: 'TA0007', name: 'System Information Discovery', offlineCapable: true, prereqStage: false,
    description: 'Adversaries enumerate OS details, hardware, domain membership, and configuration to plan further attack stages.',
    atomicTests: [
      { id: 'T1082-1', name: 'systeminfo.exe Enumeration', description: 'Runs systeminfo.exe to gather OS version, hotfixes, memory, and domain details.' },
      { id: 'T1082-2', name: 'WMIC System Discovery', description: 'Uses wmic.exe to query OS, BIOS, and hardware class information.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1\n  Image IN ("*\\\\systeminfo.exe","*\\\\wmic.exe","*\\\\msinfo32.exe")\n| table _time, Computer, User, Image, CommandLine, ParentImage`,
      ],
      vql: [
        `SELECT * FROM Artifact.Generic.System.Info()`,
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE Name =~ "(?i)(systeminfo|wmic|msinfo32).exe"`,
      ],
      powershell: [
        `Get-ComputerInfo | Select-Object WindowsProductName, OsVersion, CsName,\n  CsDomain, CsManufacturer, BiosVersion | Format-List`,
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |\n  Where-Object {$_.Message -match '(systeminfo|wmic).exe'} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1016', tactic: 'TA0007', name: 'Network Config Discovery', offlineCapable: true, prereqStage: false,
    description: 'Adversaries enumerate network adapters, routing tables, ARP caches, and active connections to map the target environment.',
    atomicTests: [
      { id: 'T1016-1', name: 'ipconfig / arp / netstat', description: 'Runs ipconfig /all, arp -a, and netstat -ano to fully enumerate network configuration and connections.' },
      { id: 'T1016-2', name: 'WMI Network Adapter Query', description: 'Uses WMIC to query Win32_NetworkAdapterConfiguration for adapter and IP details.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1\n  Image IN ("*\\\\ipconfig.exe","*\\\\netstat.exe","*\\\\arp.exe","*\\\\net.exe","*\\\\nslookup.exe")\n| table _time, Computer, User, Image, CommandLine, ParentImage`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Network.Netstat()\nWHERE Status = "ESTABLISHED"`,
        `SELECT * FROM Artifact.Windows.Network.ArpCache()`,
      ],
      powershell: [
        `Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer | Format-List`,
        `Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} |\n  ForEach-Object { $proc = Get-Process -Id $_.OwningProcess -EA SilentlyContinue\n    [PSCustomObject]@{ Process=$proc.Name; PID=$_.OwningProcess\n      Remote="$($_.RemoteAddress):$($_.RemotePort)" } } | Format-Table`,
      ]
    }
  },
  {
    id: 'T1069.002', tactic: 'TA0007', name: 'Domain Group Discovery', offlineCapable: true, prereqStage: false,
    description: 'Adversaries enumerate domain groups (especially privileged ones like Domain Admins) to identify high-value accounts for targeting.',
    atomicTests: [
      { id: 'T1069.002-1', name: 'net group Domain Admins', description: 'Runs net group "Domain Admins" /domain to list privileged group members.' },
      { id: 'T1069.002-2', name: 'PowerView Get-DomainGroup', description: 'Uses PowerView\'s Get-DomainGroup to enumerate all domain groups and members.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1\n  Image="*\\\\net.exe" CommandLine IN ("*group*","*localgroup*")\n| table _time, Computer, User, CommandLine`,
        `index=wineventlog EventCode IN (4798, 4799)\n| table _time, ComputerName, SubjectUserName, TargetUserName, Message`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE CommandLine =~ "(?i)net.*(group|localgroup).*(domain admins|enterprise admins|administrators)"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4798} |\n  Select-Object TimeCreated, Message | Format-List`,
        `# Enumerate high-value groups (run as analyst on domain system)\nGet-ADGroupMember "Domain Admins" -Recursive |\n  Select-Object Name, SamAccountName, ObjectClass | Format-Table`,
      ]
    }
  },
  {
    id: 'T1021.001', tactic: 'TA0008', name: 'Remote Desktop Protocol', offlineCapable: true, prereqStage: false,
    description: 'Adversaries use RDP with valid credentials to move laterally to other hosts, often enabling interactive access and further credential harvesting.',
    atomicTests: [
      { id: 'T1021.001-1', name: 'RDP Session to Lateral Host', description: 'Initiates an RDP session using mstsc.exe with supplied credentials to a target host.' },
    ],
    huntPack: {
      splunk: [
        `index=wineventlog EventCode=4624 LogonType=10\n| table _time, ComputerName, TargetUserName, IpAddress, LogonType`,
        `index=wineventlog EventCode=4778\n| table _time, ComputerName, AccountName, ClientName, ClientAddress`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(\n  EvtxGlob="**\\\\Security.evtx", IdRegex="4624")\nWHERE LogonType = "10"`,
        `SELECT * FROM Artifact.Windows.Network.Netstat()\nWHERE RemotePort = "3389"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |\n  Where-Object {$_.Message -match 'Logon Type:\\s+10'} |\n  Select-Object TimeCreated, Message | Format-List`,
        `Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' |\n  Where-Object {$_.Id -eq 1149} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1021.002', tactic: 'TA0008', name: 'SMB / Admin Shares', offlineCapable: true, prereqStage: false,
    description: 'Adversaries use SMB to connect to administrative shares (C$, ADMIN$, IPC$) for lateral movement, file staging, and remote execution.',
    atomicTests: [
      { id: 'T1021.002-1', name: 'Map Admin Share via net use', description: 'Uses net use to map \\\\target\\C$ with valid credentials for file transfer staging.' },
      { id: 'T1021.002-2', name: 'Remote Execution via SMB + sc.exe', description: 'Copies a service binary to ADMIN$ via SMB then creates and starts a remote service with sc.exe.' },
    ],
    huntPack: {
      splunk: [
        `index=wineventlog EventCode=5140\n  ShareName IN ("*\\\\ADMIN$","*\\\\C$","*\\\\IPC$")\n| table _time, ComputerName, SubjectUserName, ShareName, IpAddress`,
        `index=wineventlog EventCode=7045\n| rex field=Message "Service Name:\\\\s+(?P<svc>[^\\\\n]+)"\n| table _time, ComputerName, svc, Message`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.EventLogs.EvtxHunter(\n  EvtxGlob="**\\\\Security.evtx", IdRegex="5140")\nWHERE ShareName =~ "(ADMIN|C)\\\\$"`,
        `SELECT * FROM Artifact.Windows.System.Services()\nWHERE StartMode = "Manual" AND State = "Running"`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5140} |\n  Where-Object {$_.Message -match 'ADMIN\\$|C\\$'} |\n  Select-Object TimeCreated, Message | Format-List`,
        `Get-SmbOpenFile | Select-Object ClientComputerName, ClientUserName, Path | Format-Table`,
      ]
    }
  },
  {
    id: 'T1071.001', tactic: 'TA0011', name: 'C2 over HTTP/HTTPS', offlineCapable: false, prereqStage: false,
    description: 'Adversaries blend C2 traffic within legitimate web traffic using HTTP/S. Indicators include beaconing patterns, unusual user-agents, and non-browser processes making HTTP connections.',
    atomicTests: [
      { id: 'T1071.001-1', name: 'PowerShell Beaconing Simulation', description: 'Simulates C2 beaconing by sending periodic HTTP requests with Invoke-WebRequest at fixed intervals.' },
      { id: 'T1071.001-2', name: 'Malicious User-Agent HTTP Request', description: 'Makes HTTP request with a known-bad or suspicious user-agent string to a test endpoint.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=3\n  DestinationPort IN (80, 443, 8080, 8443)\n  Image!="*\\\\chrome.exe" Image!="*\\\\firefox.exe" Image!="*\\\\msedge.exe"\n| stats count, dc(DestinationIp) as uniq_ips, avg(DestinationPort) as avg_port\n    by Image, Computer\n| sort - count`,
        `index=proxy sourcetype=web_traffic\n| stats count, stdev(bytes) as jitter, avg(bytes) as avg_bytes\n    by src_ip, dest_ip, dest_port\n| where jitter < 200 AND count > 30\n| sort - count`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Network.Netstat()\nWHERE RemotePort IN ("80","443","8080","8443")\n  AND NOT Process =~ "(?i)(chrome|firefox|edge|svchost|MicrosoftEdge).exe"`,
        `SELECT * FROM Artifact.Windows.System.DNSCache()\nWHERE NOT Answer =~ "(?i)(microsoft|windows|google|akamai|cloudflare|cdn)"`,
      ],
      powershell: [
        `Get-NetTCPConnection -State Established |\n  Where-Object {$_.RemotePort -in @(80,443,8080,8443)} |\n  ForEach-Object { $proc = Get-Process -Id $_.OwningProcess -EA SilentlyContinue\n    [PSCustomObject]@{ Process=$proc.Name; PID=$_.OwningProcess\n      Remote="$($_.RemoteAddress):$($_.RemotePort)" } } |\n  Where-Object {$_.Process -notmatch '(?i)(chrome|firefox|edge|svchost)'} | Format-Table`,
        `Get-DnsClientCache |\n  Where-Object {$_.Data -notmatch '(?i)(microsoft|windows|google|akamai|cloudflare)'} |\n  Select-Object Name, Data, TimeToLive | Format-Table`,
      ]
    }
  },
  {
    id: 'T1048.003', tactic: 'TA0010', name: 'Exfil via Unencrypted Protocol', offlineCapable: false, prereqStage: false,
    description: 'Adversaries exfiltrate data using FTP, HTTP, or DNS to avoid encrypted channel detection. May use certutil or bitsadmin as LOLBins to blend in.',
    atomicTests: [
      { id: 'T1048.003-1', name: 'Data Exfil via FTP', description: 'Uses Windows ftp.exe with a script file to upload collected data to an external FTP server.' },
      { id: 'T1048.003-2', name: 'Exfil via certutil + HTTP', description: 'Base64-encodes a file with certutil -encode then POSTs it to an external server via Invoke-WebRequest.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=3 DestinationPort IN (20, 21, 69)\n| table _time, Computer, User, Image, DestinationIp, DestinationPort`,
        `index=sysmon EventCode=1\n  Image="*\\\\certutil.exe" CommandLine IN ("*-encode*","*-decode*","*-urlcache*")\n| table _time, Computer, User, CommandLine`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Network.Netstat()\nWHERE RemotePort IN ("20","21","69")`,
        `SELECT * FROM Artifact.Windows.System.Pslist()\nWHERE CommandLine =~ "(?i)certutil.*(encode|decode|urlcache)"`,
      ],
      powershell: [
        `Get-NetTCPConnection |\n  Where-Object {$_.RemotePort -in @(20,21)} |\n  ForEach-Object { $proc = Get-Process -Id $_.OwningProcess -EA SilentlyContinue\n    [PSCustomObject]@{Process=$proc.Name; RemoteIP=$_.RemoteAddress} } | Format-Table`,
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |\n  Where-Object {$_.Message -match 'certutil.*(encode|urlcache)'} |\n  Select-Object TimeCreated, Message | Format-List`,
      ]
    }
  },
  {
    id: 'T1486', tactic: 'TA0040', name: 'Data Encrypted for Impact', offlineCapable: true, prereqStage: false,
    description: 'Adversaries encrypt files to render them inaccessible and demand ransom. Often preceded by shadow copy deletion and backup interference.',
    atomicTests: [
      { id: 'T1486-1', name: 'File Encryption Simulation', description: 'Encrypts files in a staging directory using a test script, simulating ransomware file modification behaviour.' },
      { id: 'T1486-2', name: 'Shadow Copy Deletion via vssadmin', description: 'Runs vssadmin delete shadows /all /quiet to destroy VSS shadow copies — a near-universal ransomware precursor.' },
      { id: 'T1486-3', name: 'Disable Windows Recovery', description: 'Uses bcdedit /set recoveryenabled No to prevent boot-time recovery, then drops ransom note files.' },
    ],
    huntPack: {
      splunk: [
        `index=sysmon EventCode=1\n  Image IN ("*\\\\vssadmin.exe","*\\\\bcdedit.exe","*\\\\wbadmin.exe")\n  CommandLine IN ("*delete*shadows*","*recoveryenabled*","*delete*catalog*")\n| table _time, Computer, User, Image, CommandLine`,
        `index=sysmon EventCode=11\n| stats count by Computer, Image\n| where count > 500\n| sort - count`,
      ],
      vql: [
        `SELECT * FROM Artifact.Windows.Forensics.Prefetch()\nWHERE Executable =~ "(?i)(vssadmin|bcdedit|wbadmin|cipher)"\n  AND Arguments =~ "(?i)(delete|recoveryenabled|catalog)"`,
        `SELECT count(FullPath) as total, split(FullPath,".")[-1] as ext\nFROM glob(globs="C:\\\\Users\\\\**\\\\*")\nGROUP BY ext\nORDER BY total DESC LIMIT 30`,
      ],
      powershell: [
        `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |\n  Where-Object {$_.Message -match 'vssadmin.*delete|bcdedit.*recoveryenabled|wbadmin.*delete'} |\n  Select-Object TimeCreated, Message | Format-List`,
        `# Look for mass file modification events\nGet-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=2} |\n  Group-Object { $_.TimeCreated.ToString("HH:mm") } |\n  Sort-Object Count -Descending | Select-Object -First 10 Name, Count | Format-Table`,
      ]
    }
  },
];

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function CodeBlock({ code, lang }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  const langColors = { splunk: C.amber, vql: C.teal, powershell: C.blue };
  return (
    <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, marginBottom: 10, overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', borderBottom: `1px solid ${C.border}`, background: C.elevated }}>
        <span style={{ fontSize: 11, fontFamily: 'monospace', color: langColors[lang] || C.textSec, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase' }}>{lang}</span>
        <button onClick={copy} style={{ background: 'none', border: `1px solid ${C.border}`, color: copied ? C.accent : C.textSec, cursor: 'pointer', fontSize: 11, padding: '2px 10px', borderRadius: 4, fontFamily: 'monospace', transition: 'color 0.2s' }}>
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>
      <pre style={{ margin: 0, padding: '12px 14px', fontSize: 12, lineHeight: 1.65, color: C.text, fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace", overflowX: 'auto', whiteSpace: 'pre' }}>
        {code}
      </pre>
    </div>
  );
}

function TacticBadge({ tacticId, small }) {
  const t = TACTIC_META[tacticId];
  if (!t) return null;
  return (
    <span style={{ display: 'inline-block', background: `${t.color}18`, color: t.color, border: `1px solid ${t.color}40`, borderRadius: 4, padding: small ? '1px 6px' : '2px 8px', fontSize: small ? 10 : 11, fontFamily: 'monospace', fontWeight: 600, whiteSpace: 'nowrap', letterSpacing: 0.5 }}>
      {t.name}
    </span>
  );
}

function StatusDot({ status }) {
  const map = { pending: C.textMuted, running: C.amber, complete: C.accent, failed: C.red };
  return <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: map[status] || C.textMuted, flexShrink: 0, marginRight: 6 }} />;
}

export default function BlueTeamTrainer() {
  const [activeTab, setActiveTab] = useState('browser');
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [detailTab, setDetailTab] = useState('tests');
  const [huntPackTab, setHuntPackTab] = useState('splunk');
  const [scenarioChain, setScenarioChain] = useState([]);
  const [sessionLog, setSessionLog] = useState([]);
  const [scenarioName, setScenarioName] = useState('Unnamed Scenario');
  const [savedScenarios, setSavedScenarios] = useState([]);
  const [apiBase, setApiBase] = useState('http://localhost:8000');
  const [mockMode, setMockMode] = useState(true);
  const [detonatingId, setDetonatingId] = useState(null);
  const [search, setSearch] = useState('');
  const [chainRunning, setChainRunning] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [expandedLogId, setExpandedLogId] = useState(null);
  const [connectivityFilter, setConnectivityFilter] = useState('all');
  const chainRef = useRef(scenarioChain);
  chainRef.current = scenarioChain;

  const tactics = Object.entries(TACTIC_META);
  const filtered = TECHNIQUES.filter(t => {
    const matchTactic = !selectedTactic || t.tactic === selectedTactic;
    const q = search.toLowerCase();
    const matchSearch = !q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q);
    let matchConnectivity = true;
    if (connectivityFilter === 'offline') matchConnectivity = t.offlineCapable === true;
    else if (connectivityFilter === 'staged') matchConnectivity = t.offlineCapable === false && t.prereqStage === true;
    else if (connectivityFilter === 'online') matchConnectivity = t.offlineCapable === false && t.prereqStage === false;
    return matchTactic && matchSearch && matchConnectivity;
  });

  const tacticCounts = {};
  TECHNIQUES.forEach(t => { tacticCounts[t.tactic] = (tacticCounts[t.tactic] || 0) + 1; });

  const handleDetonate = useCallback(async (technique, atomicTest) => {
    setDetonatingId(atomicTest.id);
    const start = Date.now();
    if (mockMode) {
      await new Promise(r => setTimeout(r, 1400 + Math.random() * 800));
      const success = Math.random() > 0.12;
      const entry = { id: uid(), timestamp: new Date(), technique, atomicTest, status: success ? 'success' : 'failed', duration: Date.now() - start, stdout: success ? 'Mock execution OK' : '', stderr: success ? '' : 'Mock failure for UI testing' };
      setSessionLog(prev => [entry, ...prev]);
      setDetonatingId(null);
    } else {
      try {
        const res = await fetch(`${apiBase}/detonate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ technique_id: technique.id, test_id: atomicTest.id })
        });
        const data = await res.json();
        const entry = { id: uid(), timestamp: new Date(), technique, atomicTest, status: data.success ? 'success' : 'failed', duration: Date.now() - start, stdout: data.stdout || '', stderr: data.stderr || '', httpStatus: res.status };
        setSessionLog(prev => [entry, ...prev]);
      } catch (err) {
        const entry = { id: uid(), timestamp: new Date(), technique, atomicTest, status: 'failed', duration: Date.now() - start, stdout: '', stderr: `Network error: ${err.message}`, httpStatus: 0 };
        setSessionLog(prev => [entry, ...prev]);
      }
      setDetonatingId(null);
    }
  }, [mockMode, apiBase]);

  const handleCheckPrereqs = useCallback(async (technique, atomicTest) => {
    if (mockMode) {
      const entry = { id: uid(), timestamp: new Date(), technique, atomicTest, status: 'success', duration: 500, stdout: 'Mock prereq check OK', stderr: '', isPrereqCheck: true };
      setSessionLog(prev => [entry, ...prev]);
      return;
    }
    try {
      const testNum = atomicTest.id.split('-').pop();
      const res = await fetch(`${apiBase}/check-prereqs/${technique.id}/${testNum}`);
      const data = await res.json();
      const entry = { id: uid(), timestamp: new Date(), technique, atomicTest, status: data.success ? 'success' : 'failed', duration: 0, stdout: data.stdout || '', stderr: data.stderr || '', isPrereqCheck: true };
      setSessionLog(prev => [entry, ...prev]);
    } catch (err) {
      const entry = { id: uid(), timestamp: new Date(), technique, atomicTest, status: 'failed', duration: 0, stdout: '', stderr: `Network error: ${err.message}`, isPrereqCheck: true };
      setSessionLog(prev => [entry, ...prev]);
    }
  }, [mockMode, apiBase]);

  const addToChain = (technique, test) => {
    setScenarioChain(prev => [...prev, { id: uid(), technique, selectedTest: test, status: 'pending', detonatedAt: null }]);
  };

  const removeFromChain = (id) => setScenarioChain(prev => prev.filter(i => i.id !== id));

  const moveChainItem = (id, dir) => {
    setScenarioChain(prev => {
      const arr = [...prev];
      const idx = arr.findIndex(i => i.id === id);
      const newIdx = idx + dir;
      if (newIdx < 0 || newIdx >= arr.length) return arr;
      [arr[idx], arr[newIdx]] = [arr[newIdx], arr[idx]];
      return arr;
    });
  };

  const changeChainTest = (chainId, test) => {
    setScenarioChain(prev => prev.map(i => i.id === chainId ? { ...i, selectedTest: test } : i));
  };

  const runChain = async () => {
    setChainRunning(true);
    setActiveTab('scenarios');
    for (let i = 0; i < chainRef.current.length; i++) {
      const item = chainRef.current[i];
      setScenarioChain(prev => prev.map(x => x.id === item.id ? { ...x, status: 'running' } : x));
      if (mockMode) {
        await new Promise(r => setTimeout(r, 1200 + Math.random() * 1000));
        const success = Math.random() > 0.1;
        setScenarioChain(prev => prev.map(x => x.id === item.id ? { ...x, status: success ? 'complete' : 'failed', detonatedAt: new Date() } : x));
        const entry = { id: uid(), timestamp: new Date(), technique: item.technique, atomicTest: item.selectedTest, status: success ? 'success' : 'failed', duration: 1200 };
        setSessionLog(prev => [entry, ...prev]);
      } else {
        try {
          await fetch(`${apiBase}/detonate`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ technique_id: item.technique.id, test_id: item.selectedTest.id })
          });
          setScenarioChain(prev => prev.map(x => x.id === item.id ? { ...x, status: 'complete', detonatedAt: new Date() } : x));
        } catch {
          setScenarioChain(prev => prev.map(x => x.id === item.id ? { ...x, status: 'failed', detonatedAt: new Date() } : x));
        }
      }
    }
    setChainRunning(false);
  };

  const saveScenario = () => {
    if (!scenarioChain.length) return;
    const scenario = { id: uid(), name: scenarioName, chain: scenarioChain.map(i => ({ technique: i.technique, selectedTest: i.selectedTest })), createdAt: new Date() };
    setSavedScenarios(prev => [scenario, ...prev]);
  };

  const loadScenario = (scenario) => {
    setScenarioChain(scenario.chain.map(i => ({ id: uid(), technique: i.technique, selectedTest: i.selectedTest, status: 'pending', detonatedAt: null })));
    setScenarioName(scenario.name);
    setActiveTab('scenarios');
  };

  const resetChain = () => setScenarioChain(prev => prev.map(i => ({ ...i, status: 'pending', detonatedAt: null })));

  const s = { fontFamily: "'JetBrains Mono', 'Fira Code', monospace" };

  return (
    <div style={{ ...s, background: C.bg, color: C.text, height: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden', fontSize: 13 }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #21262d; border-radius: 3px; }
        input, textarea, select { font-family: inherit !important; }
        button { font-family: inherit !important; }
      `}</style>

      {/* Header */}
      <div style={{ background: C.surface, borderBottom: `1px solid ${C.border}`, padding: '0 20px', display: 'flex', alignItems: 'center', gap: 24, flexShrink: 0, height: 52 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 28, height: 28, borderRadius: 6, background: C.accentDim, border: `1px solid ${C.accent}40`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <polygon points="8,1 15,5 15,11 8,15 1,11 1,5" stroke={C.accent} strokeWidth="1.2" fill="none"/>
              <polygon points="8,4 12,6.5 12,9.5 8,12 4,9.5 4,6.5" fill={C.accent} opacity="0.4"/>
              <circle cx="8" cy="8" r="2" fill={C.accent}/>
            </svg>
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: C.accent, letterSpacing: 1 }}>BLUE TEAM TRAINER</div>
            <div style={{ fontSize: 9, color: C.textMuted, letterSpacing: 2, marginTop: -2 }}>ATT&CK / ATOMIC / HUNT</div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 4, marginLeft: 12 }}>
          {[['browser','ATT&CK Browser'],['scenarios','Scenario Builder'],['log','Session Log']].map(([key, label]) => (
            <button key={key} onClick={() => setActiveTab(key)} style={{ background: activeTab === key ? C.accentDim : 'none', border: `1px solid ${activeTab === key ? C.accent+'50' : 'transparent'}`, color: activeTab === key ? C.accent : C.textSec, padding: '5px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 12, fontWeight: activeTab === key ? 600 : 400, transition: 'all 0.15s' }}>
              {label}
              {key === 'scenarios' && scenarioChain.length > 0 && <span style={{ marginLeft: 6, background: C.accent, color: '#000', borderRadius: 10, fontSize: 9, padding: '1px 5px', fontWeight: 700 }}>{scenarioChain.length}</span>}
              {key === 'log' && sessionLog.length > 0 && <span style={{ marginLeft: 6, background: C.elevated, color: C.textSec, borderRadius: 10, fontSize: 9, padding: '1px 5px' }}>{sessionLog.length}</span>}
            </button>
          ))}
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: C.elevated, border: `1px solid ${C.border}`, borderRadius: 5, padding: '4px 10px' }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: mockMode ? C.amber : C.accent, display: 'inline-block', flexShrink: 0 }} />
            <span style={{ fontSize: 11, color: C.textSec }}>{mockMode ? 'Mock Mode' : 'Live Mode'}</span>
          </div>
          <button onClick={() => setShowSettings(s => !s)} style={{ background: showSettings ? C.elevated : 'none', border: `1px solid ${showSettings ? C.border : 'transparent'}`, color: C.textSec, cursor: 'pointer', padding: '5px 10px', borderRadius: 5, fontSize: 12 }}>
            ⚙ Settings
          </button>
        </div>
      </div>

      {/* Settings Panel */}
      {showSettings && (
        <div style={{ background: C.elevated, borderBottom: `1px solid ${C.border}`, padding: '12px 20px', display: 'flex', alignItems: 'center', gap: 20, flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: C.textSec }}>Backend API:</span>
            <input value={apiBase} onChange={e => setApiBase(e.target.value)} style={{ background: C.bg, border: `1px solid ${C.border}`, color: C.text, padding: '4px 10px', borderRadius: 4, fontSize: 12, width: 220 }} placeholder="http://localhost:8000" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: C.textSec }}>Mode:</span>
            <button onClick={() => setMockMode(m => !m)} style={{ background: mockMode ? `${C.amber}20` : `${C.accent}20`, border: `1px solid ${mockMode ? C.amber+'50' : C.accent+'50'}`, color: mockMode ? C.amber : C.accent, padding: '4px 12px', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontWeight: 600 }}>
              {mockMode ? '⚡ Mock Mode (no backend)' : '🔴 Live Mode (backend required)'}
            </button>
          </div>
          <span style={{ fontSize: 11, color: C.textMuted }}>Backend: FastAPI server with WinRM → target VM. See README for setup.</span>
        </div>
      )}

      {/* Main Content */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* ATT&CK Browser Tab */}
        {activeTab === 'browser' && (
          <>
            {/* Tactic Sidebar */}
            <div style={{ width: 190, background: C.surface, borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
              <div style={{ padding: '10px 12px', borderBottom: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 9, color: C.textMuted, letterSpacing: 2, fontWeight: 600 }}>TACTICS</div>
              </div>
              <div style={{ overflowY: 'auto', flex: 1 }}>
                <button onClick={() => setSelectedTactic(null)} style={{ width: '100%', textAlign: 'left', background: !selectedTactic ? C.accentDim : 'none', border: 'none', borderBottom: `1px solid ${C.border}`, color: !selectedTactic ? C.accent : C.textSec, padding: '9px 14px', cursor: 'pointer', fontSize: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>All Techniques</span>
                  <span style={{ fontSize: 10, color: C.textMuted }}>{TECHNIQUES.length}</span>
                </button>
                {tactics.map(([tid, meta]) => (
                  <button key={tid} onClick={() => setSelectedTactic(tid === selectedTactic ? null : tid)} style={{ width: '100%', textAlign: 'left', background: selectedTactic === tid ? `${meta.color}15` : 'none', border: 'none', borderBottom: `1px solid ${C.border}20`, borderLeft: selectedTactic === tid ? `2px solid ${meta.color}` : '2px solid transparent', color: selectedTactic === tid ? meta.color : C.textSec, padding: '8px 12px', cursor: 'pointer', fontSize: 11.5, display: 'flex', justifyContent: 'space-between', alignItems: 'center', transition: 'all 0.12s' }}>
                    <span style={{ lineHeight: 1.3 }}>{meta.name}</span>
                    <span style={{ fontSize: 10, color: C.textMuted, marginLeft: 4 }}>{tacticCounts[tid] || 0}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Technique Grid + Detail */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              {/* Search + stats bar */}
              <div style={{ padding: '10px 16px', borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0, background: C.surface, flexWrap: 'wrap' }}>
                <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search technique ID or name..." style={{ flex: 1, minWidth: 200, background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: '6px 12px', borderRadius: 5, fontSize: 12 }} />
                <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                  {[
                    ['all', 'All', C.textSec],
                    ['offline', '○ Offline', C.accent],
                    ['staged', '◐ Staged', C.amber],
                    ['online', '● Online', C.red],
                  ].map(([key, label, color]) => (
                    <button key={key} onClick={() => setConnectivityFilter(key)} title={
                      key === 'offline' ? 'Works on a fully isolated victim' :
                      key === 'staged' ? 'Works offline if Check Prereqs has been run with internet, then victim snapshotted' :
                      key === 'online' ? 'Requires internet at runtime' : 'Show all techniques'
                    } style={{ background: connectivityFilter === key ? `${color}18` : 'none', border: `1px solid ${connectivityFilter === key ? color + '60' : C.border}`, color: connectivityFilter === key ? color : C.textSec, padding: '4px 10px', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontWeight: connectivityFilter === key ? 600 : 400 }}>
                      {label}
                    </button>
                  ))}
                </div>
                <span style={{ fontSize: 11, color: C.textMuted, whiteSpace: 'nowrap' }}>{filtered.length} technique{filtered.length !== 1 ? 's' : ''}</span>
                {selectedTactic && <button onClick={() => setSelectedTactic(null)} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.textSec, cursor: 'pointer', padding: '4px 10px', borderRadius: 4, fontSize: 11 }}>✕ Clear tactic</button>}
              </div>

              <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
                {/* Cards Grid */}
                <div style={{ flex: selectedTechnique ? '0 0 360px' : 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {filtered.map(t => {
                    const meta = TACTIC_META[t.tactic];
                    const isSelected = selectedTechnique?.id === t.id;
                    const inChain = scenarioChain.some(c => c.technique.id === t.id);
                    return (
                      <div key={t.id} onClick={() => { setSelectedTechnique(isSelected ? null : t); setDetailTab('tests'); setHuntPackTab('splunk'); }}
                        style={{ background: isSelected ? C.accentDim : C.surface, border: `1px solid ${isSelected ? C.accent+'60' : C.border}`, borderRadius: 7, padding: '10px 14px', cursor: 'pointer', transition: 'all 0.12s', position: 'relative' }}>
                        {inChain && <span style={{ position: 'absolute', top: 8, right: 10, fontSize: 9, color: C.accent, fontWeight: 700, letterSpacing: 1 }}>IN CHAIN</span>}
                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                          <div style={{ flex: 1 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                              <span style={{ fontSize: 10, color: C.textMuted, fontWeight: 600, letterSpacing: 0.5 }}>{t.id}</span>
                              <TacticBadge tacticId={t.tactic} small />
                              {t.offlineCapable === false && t.prereqStage === false && (
                                <span title="This technique requires the victim to have internet access at runtime - won't work on a fully isolated network" style={{ display: 'inline-block', background: `${C.red}18`, color: C.red, border: `1px solid ${C.red}40`, borderRadius: 4, padding: '1px 6px', fontSize: 10, fontFamily: 'monospace', fontWeight: 600, letterSpacing: 0.5 }}>● ONLINE</span>
                              )}
                              {t.offlineCapable === false && t.prereqStage === true && (
                                <span title="Will work offline if you run 'Check Prereqs' first while the victim has internet, then snapshot" style={{ display: 'inline-block', background: `${C.amber}18`, color: C.amber, border: `1px solid ${C.amber}40`, borderRadius: 4, padding: '1px 6px', fontSize: 10, fontFamily: 'monospace', fontWeight: 600, letterSpacing: 0.5 }}>◐ STAGED</span>
                              )}
                              {t.offlineCapable === true && (
                                <span title="Works on a fully network-isolated victim" style={{ display: 'inline-block', background: `${C.accent}18`, color: C.accent, border: `1px solid ${C.accent}40`, borderRadius: 4, padding: '1px 6px', fontSize: 10, fontFamily: 'monospace', fontWeight: 600, letterSpacing: 0.5 }}>○ OFFLINE</span>
                              )}
                            </div>
                            <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 4 }}>{t.name}</div>
                            {!selectedTechnique && <div style={{ fontSize: 11, color: C.textSec, lineHeight: 1.5 }}>{t.description.slice(0, 90)}…</div>}
                          </div>
                          <div style={{ fontSize: 10, color: C.textMuted, textAlign: 'right', flexShrink: 0, marginTop: 2 }}>{t.atomicTests.length} test{t.atomicTests.length !== 1 ? 's' : ''}</div>
                        </div>
                      </div>
                    );
                  })}
                  {filtered.length === 0 && (
                    <div style={{ textAlign: 'center', color: C.textMuted, padding: 40, fontSize: 12 }}>No techniques match your filter.</div>
                  )}
                </div>

                {/* Technique Detail Panel */}
                {selectedTechnique && (
                  <div style={{ flex: 1, borderLeft: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                    {/* Detail Header */}
                    <div style={{ padding: '12px 16px', borderBottom: `1px solid ${C.border}`, flexShrink: 0, background: C.surface }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 11, color: C.textMuted, fontWeight: 600 }}>{selectedTechnique.id}</span>
                        <TacticBadge tacticId={selectedTechnique.tactic} small />
                        {selectedTechnique.offlineCapable === false && selectedTechnique.prereqStage === false && (
                          <span style={{ display: 'inline-block', background: `${C.red}18`, color: C.red, border: `1px solid ${C.red}40`, borderRadius: 4, padding: '1px 6px', fontSize: 10, fontFamily: 'monospace', fontWeight: 600 }}>● ONLINE</span>
                        )}
                        {selectedTechnique.offlineCapable === false && selectedTechnique.prereqStage === true && (
                          <span style={{ display: 'inline-block', background: `${C.amber}18`, color: C.amber, border: `1px solid ${C.amber}40`, borderRadius: 4, padding: '1px 6px', fontSize: 10, fontFamily: 'monospace', fontWeight: 600 }}>◐ STAGED</span>
                        )}
                        {selectedTechnique.offlineCapable === true && (
                          <span style={{ display: 'inline-block', background: `${C.accent}18`, color: C.accent, border: `1px solid ${C.accent}40`, borderRadius: 4, padding: '1px 6px', fontSize: 10, fontFamily: 'monospace', fontWeight: 600 }}>○ OFFLINE</span>
                        )}
                        <button onClick={() => setSelectedTechnique(null)} style={{ marginLeft: 'auto', background: 'none', border: `1px solid ${C.border}`, color: C.textSec, cursor: 'pointer', padding: '2px 8px', borderRadius: 4, fontSize: 11 }}>✕</button>
                      </div>
                      <div style={{ fontSize: 15, fontWeight: 700, color: C.text, marginBottom: 5 }}>{selectedTechnique.name}</div>
                      <div style={{ fontSize: 11.5, color: C.textSec, lineHeight: 1.6 }}>{selectedTechnique.description}</div>
                      {selectedTechnique.offlineCapable === false && selectedTechnique.prereqStage === false && (
                        <div style={{ marginTop: 10, padding: '8px 10px', background: `${C.red}10`, border: `1px solid ${C.red}30`, borderRadius: 5, fontSize: 11, color: C.text, lineHeight: 1.6 }}>
                          <strong style={{ color: C.red }}>Requires internet at runtime.</strong> The atomic test contacts an external host (downloads, beaconing, or exfil to a public endpoint) and will fail on a network-isolated victim. Either expose the victim to the internet briefly or expect this test to fail.
                        </div>
                      )}
                      {selectedTechnique.offlineCapable === false && selectedTechnique.prereqStage === true && (
                        <div style={{ marginTop: 10, padding: '8px 10px', background: `${C.amber}10`, border: `1px solid ${C.amber}30`, borderRadius: 5, fontSize: 11, color: C.text, lineHeight: 1.6 }}>
                          <strong style={{ color: C.amber }}>Needs payload staged.</strong> Click <strong>⚙ Check Prereqs</strong> while the victim has internet — this downloads the required tooling (procdump, mimikatz, rubeus, etc.) into <code style={{ background: C.bg, padding: '0 4px', borderRadius: 3 }}>C:\\AtomicRedTeam\\ExternalPayloads</code>. Take a snapshot afterwards and the test will work on every revert without needing internet again.
                        </div>
                      )}
                    </div>

                    {/* Detail Tabs */}
                    <div style={{ display: 'flex', borderBottom: `1px solid ${C.border}`, flexShrink: 0, background: C.surface }}>
                      {[['tests','Atomic Tests'],['hunt','Hunt Pack']].map(([key, label]) => (
                        <button key={key} onClick={() => setDetailTab(key)} style={{ background: 'none', border: 'none', borderBottom: `2px solid ${detailTab === key ? C.accent : 'transparent'}`, color: detailTab === key ? C.accent : C.textSec, padding: '9px 16px', cursor: 'pointer', fontSize: 12, fontWeight: detailTab === key ? 600 : 400 }}>
                          {label}
                        </button>
                      ))}
                    </div>

                    <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
                      {/* Atomic Tests Panel */}
                      {detailTab === 'tests' && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                          {selectedTechnique.atomicTests.map(test => {
                            const isDetonating = detonatingId === test.id;
                            return (
                              <div key={test.id} style={{ background: C.elevated, border: `1px solid ${C.border}`, borderRadius: 7, padding: 14 }}>
                                <div style={{ fontSize: 11, color: C.textMuted, fontWeight: 600, marginBottom: 4 }}>{test.id}</div>
                                <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 6 }}>{test.name}</div>
                                <div style={{ fontSize: 11.5, color: C.textSec, lineHeight: 1.6, marginBottom: 12 }}>{test.description}</div>
                                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                  <button onClick={() => handleDetonate(selectedTechnique, test)} disabled={isDetonating} style={{ background: isDetonating ? `${C.red}15` : `${C.red}20`, border: `1px solid ${C.red}50`, color: isDetonating ? C.textSec : C.red, padding: '6px 14px', borderRadius: 5, cursor: isDetonating ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 600, opacity: isDetonating ? 0.7 : 1, transition: 'all 0.15s' }}>
                                    {isDetonating ? '⟳ Detonating…' : '⚡ Detonate'}
                                  </button>
                                  <button onClick={() => handleCheckPrereqs(selectedTechnique, test)} title="Check & install test prerequisites" style={{ background: `${C.amber}15`, border: `1px solid ${C.amber}50`, color: C.amber, padding: '6px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 12, fontWeight: 600, transition: 'all 0.15s' }}>
                                    ⚙ Check Prereqs
                                  </button>
                                  <button onClick={() => addToChain(selectedTechnique, test)} style={{ background: C.accentDim, border: `1px solid ${C.accent}50`, color: C.accent, padding: '6px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 12, fontWeight: 600, transition: 'all 0.15s' }}>
                                    + Add to Chain
                                  </button>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {/* Hunt Pack Panel */}
                      {detailTab === 'hunt' && (
                        <div>
                          <div style={{ display: 'flex', gap: 6, marginBottom: 14 }}>
                            {[['splunk','Splunk SPL'],['vql','Velociraptor VQL'],['powershell','PowerShell']].map(([key, label]) => {
                              const colors = { splunk: C.amber, vql: C.teal, powershell: C.blue };
                              return (
                                <button key={key} onClick={() => setHuntPackTab(key)} style={{ background: huntPackTab === key ? `${colors[key]}20` : 'none', border: `1px solid ${huntPackTab === key ? colors[key]+'60' : C.border}`, color: huntPackTab === key ? colors[key] : C.textSec, padding: '5px 12px', borderRadius: 5, cursor: 'pointer', fontSize: 11, fontWeight: huntPackTab === key ? 600 : 400, transition: 'all 0.15s' }}>
                                  {label}
                                </button>
                              );
                            })}
                          </div>

                          {huntPackTab === 'splunk' && selectedTechnique.huntPack.splunk.map((q, i) => (
                            <div key={i}>
                              <div style={{ fontSize: 10, color: C.textMuted, marginBottom: 4, letterSpacing: 1 }}>QUERY {i + 1}</div>
                              <CodeBlock code={q} lang="splunk" />
                            </div>
                          ))}
                          {huntPackTab === 'vql' && selectedTechnique.huntPack.vql.map((q, i) => (
                            <div key={i}>
                              <div style={{ fontSize: 10, color: C.textMuted, marginBottom: 4, letterSpacing: 1 }}>ARTIFACT {i + 1}</div>
                              <CodeBlock code={q} lang="vql" />
                            </div>
                          ))}
                          {huntPackTab === 'powershell' && selectedTechnique.huntPack.powershell.map((q, i) => (
                            <div key={i}>
                              <div style={{ fontSize: 10, color: C.textMuted, marginBottom: 4, letterSpacing: 1 }}>COMMAND {i + 1}</div>
                              <CodeBlock code={q} lang="powershell" />
                            </div>
                          ))}

                          <div style={{ marginTop: 10, padding: '10px 12px', background: C.elevated, border: `1px solid ${C.border}`, borderRadius: 6 }}>
                            <div style={{ fontSize: 10, color: C.textMuted, letterSpacing: 1, marginBottom: 4 }}>VELOCIRAPTOR NOTE</div>
                            <div style={{ fontSize: 11, color: C.textSec, lineHeight: 1.6 }}>VQL artifacts are designed to be run manually via the Velociraptor GUI or CLI. Navigate to your target client → New Hunt or Client Collected Artifact and select the relevant artifact from the list above. This deliberate step builds analyst proficiency in artifact selection and evidence interpretation.</div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </>
        )}

        {/* Scenario Builder Tab */}
        {activeTab === 'scenarios' && (
          <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
            {/* Chain Builder */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: `1px solid ${C.border}` }}>
              <div style={{ padding: '12px 16px', borderBottom: `1px solid ${C.border}`, background: C.surface, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
                <input value={scenarioName} onChange={e => setScenarioName(e.target.value)} style={{ background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: '6px 12px', borderRadius: 5, fontSize: 13, fontWeight: 600, flex: 1 }} />
                <span style={{ fontSize: 11, color: C.textMuted }}>{scenarioChain.length} step{scenarioChain.length !== 1 ? 's' : ''}</span>
                <button onClick={() => setActiveTab('browser')} style={{ background: C.accentDim, border: `1px solid ${C.accent}50`, color: C.accent, padding: '6px 12px', borderRadius: 5, cursor: 'pointer', fontSize: 12 }}>+ Add Technique</button>
              </div>

              {scenarioChain.length === 0 ? (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: C.textMuted, gap: 12 }}>
                  <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
                    <rect x="4" y="4" width="16" height="16" rx="3" stroke={C.textMuted} strokeWidth="1.5"/>
                    <rect x="28" y="16" width="16" height="16" rx="3" stroke={C.textMuted} strokeWidth="1.5"/>
                    <rect x="4" y="28" width="16" height="16" rx="3" stroke={C.textMuted} strokeWidth="1.5"/>
                    <path d="M20 12 H28 M36 32 V36 H28 M12 20 V28" stroke={C.textMuted} strokeWidth="1.5" strokeDasharray="3 2"/>
                  </svg>
                  <div style={{ fontSize: 13 }}>No techniques in chain</div>
                  <div style={{ fontSize: 11 }}>Browse ATT&CK techniques and add them to build an attack scenario</div>
                </div>
              ) : (
                <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
                  {scenarioChain.map((item, idx) => {
                    const meta = TACTIC_META[item.technique.tactic];
                    const statusColors = { pending: C.textMuted, running: C.amber, complete: C.accent, failed: C.red };
                    return (
                      <div key={item.id} style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
                        {/* Step indicator */}
                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
                          <div style={{ width: 28, height: 28, borderRadius: '50%', border: `2px solid ${statusColors[item.status]}`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, color: statusColors[item.status], background: item.status === 'running' ? `${C.amber}15` : 'transparent', flexShrink: 0 }}>
                            {item.status === 'complete' ? '✓' : item.status === 'failed' ? '✕' : item.status === 'running' ? '⟳' : idx + 1}
                          </div>
                          {idx < scenarioChain.length - 1 && <div style={{ width: 1, flex: 1, background: C.border, minHeight: 16, margin: '4px 0' }} />}
                        </div>

                        {/* Card */}
                        <div style={{ flex: 1, background: C.surface, border: `1px solid ${item.status === 'running' ? C.amber+'50' : item.status === 'complete' ? C.accent+'30' : item.status === 'failed' ? C.red+'30' : C.border}`, borderRadius: 7, padding: 12, marginBottom: idx < scenarioChain.length - 1 ? 0 : 0 }}>
                          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
                            <div style={{ flex: 1 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                                <span style={{ fontSize: 10, color: C.textMuted }}>{item.technique.id}</span>
                                <TacticBadge tacticId={item.technique.tactic} small />
                              </div>
                              <div style={{ fontSize: 13, fontWeight: 600 }}>{item.technique.name}</div>
                            </div>
                            <div style={{ display: 'flex', gap: 4 }}>
                              <button onClick={() => moveChainItem(item.id, -1)} disabled={idx === 0} style={{ background: 'none', border: `1px solid ${C.border}`, color: idx === 0 ? C.textMuted : C.textSec, padding: '2px 7px', borderRadius: 4, cursor: idx === 0 ? 'not-allowed' : 'pointer', fontSize: 11 }}>↑</button>
                              <button onClick={() => moveChainItem(item.id, 1)} disabled={idx === scenarioChain.length - 1} style={{ background: 'none', border: `1px solid ${C.border}`, color: idx === scenarioChain.length - 1 ? C.textMuted : C.textSec, padding: '2px 7px', borderRadius: 4, cursor: idx === scenarioChain.length - 1 ? 'not-allowed' : 'pointer', fontSize: 11 }}>↓</button>
                              <button onClick={() => removeFromChain(item.id)} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.red, padding: '2px 7px', borderRadius: 4, cursor: 'pointer', fontSize: 11 }}>✕</button>
                            </div>
                          </div>

                          <div style={{ marginBottom: 6 }}>
                            <div style={{ fontSize: 10, color: C.textMuted, marginBottom: 4, letterSpacing: 1 }}>ATOMIC TEST</div>
                            <select value={item.selectedTest.id} onChange={e => { const test = item.technique.atomicTests.find(t => t.id === e.target.value); if (test) changeChainTest(item.id, test); }} style={{ width: '100%', background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: '5px 10px', borderRadius: 4, fontSize: 11 }}>
                              {item.technique.atomicTests.map(t => (
                                <option key={t.id} value={t.id}>{t.name}</option>
                              ))}
                            </select>
                          </div>

                          {item.detonatedAt && (
                            <div style={{ fontSize: 10, color: C.textMuted }}>
                              {item.status === 'complete' ? '✓ Completed' : '✕ Failed'} at {item.detonatedAt.toLocaleTimeString()}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Chain Controls */}
              {scenarioChain.length > 0 && (
                <div style={{ padding: '12px 16px', borderTop: `1px solid ${C.border}`, background: C.surface, display: 'flex', gap: 8, flexShrink: 0 }}>
                  <button onClick={runChain} disabled={chainRunning} style={{ flex: 1, background: chainRunning ? `${C.red}10` : `${C.red}20`, border: `1px solid ${C.red}60`, color: chainRunning ? C.textSec : C.red, padding: '8px 0', borderRadius: 5, cursor: chainRunning ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 700, letterSpacing: 1 }}>
                    {chainRunning ? '⟳ RUNNING CHAIN…' : '⚡ RUN CHAIN'}
                  </button>
                  <button onClick={resetChain} disabled={chainRunning} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.textSec, padding: '8px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 12 }}>Reset</button>
                  <button onClick={saveScenario} style={{ background: C.accentDim, border: `1px solid ${C.accent}50`, color: C.accent, padding: '8px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 12, fontWeight: 600 }}>Save</button>
                  <button onClick={() => setScenarioChain([])} disabled={chainRunning} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.red, padding: '8px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 12 }}>Clear</button>
                </div>
              )}
            </div>

            {/* Saved Scenarios */}
            <div style={{ width: 280, background: C.surface, display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
              <div style={{ padding: '12px 14px', borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
                <div style={{ fontSize: 9, color: C.textMuted, letterSpacing: 2, fontWeight: 600 }}>SAVED SCENARIOS</div>
              </div>
              <div style={{ flex: 1, overflowY: 'auto', padding: 10 }}>
                {savedScenarios.length === 0 ? (
                  <div style={{ color: C.textMuted, fontSize: 11, textAlign: 'center', padding: 20 }}>No saved scenarios yet.<br/>Build a chain and click Save.</div>
                ) : savedScenarios.map(sc => (
                  <div key={sc.id} onClick={() => loadScenario(sc)} style={{ background: C.elevated, border: `1px solid ${C.border}`, borderRadius: 6, padding: 10, marginBottom: 8, cursor: 'pointer', transition: 'border-color 0.12s' }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: C.text, marginBottom: 3 }}>{sc.name}</div>
                    <div style={{ fontSize: 10, color: C.textMuted }}>{sc.chain.length} techniques · {sc.createdAt.toLocaleDateString()}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 6 }}>
                      {sc.chain.slice(0, 4).map((item, i) => (
                        <TacticBadge key={i} tacticId={item.technique.tactic} small />
                      ))}
                      {sc.chain.length > 4 && <span style={{ fontSize: 9, color: C.textMuted }}>+{sc.chain.length - 4} more</span>}
                    </div>
                  </div>
                ))}
              </div>

              {/* Built-in example scenarios */}
              <div style={{ borderTop: `1px solid ${C.border}`, padding: '10px', flexShrink: 0 }}>
                <div style={{ fontSize: 9, color: C.textMuted, letterSpacing: 2, fontWeight: 600, marginBottom: 8 }}>EXAMPLE SCENARIOS</div>
                {[
                  { name: 'Ransomware Chain', steps: ['T1059.001','T1003.001','T1070.001','T1486'] },
                  { name: 'Phishing → Persistence', steps: ['T1566.001','T1059.001','T1547.001','T1053.005'] },
                  { name: 'Lateral Movement', steps: ['T1082','T1069.002','T1021.002','T1021.001'] },
                ].map((ex, i) => (
                  <div key={i} onClick={() => {
                    const chain = ex.steps.map(id => {
                      const t = TECHNIQUES.find(t => t.id === id);
                      if (!t) return null;
                      return { id: uid(), technique: t, selectedTest: t.atomicTests[0], status: 'pending', detonatedAt: null };
                    }).filter(Boolean);
                    setScenarioChain(chain);
                    setScenarioName(ex.name);
                  }} style={{ background: C.elevated, border: `1px solid ${C.border}`, borderRadius: 5, padding: '7px 10px', marginBottom: 6, cursor: 'pointer', fontSize: 11, color: C.textSec, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>{ex.name}</span>
                    <span style={{ color: C.textMuted, fontSize: 10 }}>{ex.steps.length} steps →</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Session Log Tab */}
        {activeTab === 'log' && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ padding: '10px 16px', borderBottom: `1px solid ${C.border}`, background: C.surface, display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
              <div style={{ fontSize: 9, color: C.textMuted, letterSpacing: 2, fontWeight: 600 }}>{sessionLog.length} DETONATION{sessionLog.length !== 1 ? 'S' : ''}</div>
              {sessionLog.length > 0 && (
                <>
                  <span style={{ color: C.accent, fontSize: 11 }}>✓ {sessionLog.filter(e => e.status === 'success').length} success</span>
                  <span style={{ color: C.red, fontSize: 11 }}>✕ {sessionLog.filter(e => e.status === 'failed').length} failed</span>
                  <button onClick={() => setSessionLog([])} style={{ marginLeft: 'auto', background: 'none', border: `1px solid ${C.border}`, color: C.red, cursor: 'pointer', padding: '4px 10px', borderRadius: 4, fontSize: 11 }}>Clear Log</button>
                </>
              )}
            </div>
            {sessionLog.length === 0 ? (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: C.textMuted, fontSize: 13 }}>
                No detonations recorded yet. Run a technique or scenario to begin.
              </div>
            ) : (
              <div style={{ flex: 1, overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ background: C.surface, borderBottom: `1px solid ${C.border}`, position: 'sticky', top: 0, zIndex: 1 }}>
                      <th style={{ padding: '8px 8px', width: 24 }}></th>
                      {['Time','Technique','Test','Tactic','Status','Duration'].map(h => (
                        <th key={h} style={{ padding: '8px 14px', textAlign: 'left', fontSize: 10, color: C.textMuted, letterSpacing: 1, fontWeight: 600, whiteSpace: 'nowrap' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sessionLog.map((entry, i) => {
                      const expanded = expandedLogId === entry.id;
                      const hasOutput = (entry.stdout && entry.stdout.length > 0) || (entry.stderr && entry.stderr.length > 0);
                      return (
                        <React.Fragment key={entry.id}>
                          <tr onClick={() => hasOutput && setExpandedLogId(expanded ? null : entry.id)} style={{ borderBottom: `1px solid ${C.border}20`, background: i % 2 === 0 ? 'transparent' : `${C.surface}80`, cursor: hasOutput ? 'pointer' : 'default' }}>
                            <td style={{ padding: '9px 8px', textAlign: 'center', color: C.textMuted, fontSize: 11 }}>{hasOutput ? (expanded ? '▼' : '▶') : ''}</td>
                            <td style={{ padding: '9px 14px', color: C.textSec, whiteSpace: 'nowrap' }}>{entry.timestamp.toLocaleTimeString()}</td>
                            <td style={{ padding: '9px 14px', color: C.text, fontWeight: 500 }}>
                              <span style={{ color: C.textMuted, fontFamily: 'monospace', marginRight: 8 }}>{entry.technique.id}</span>
                              {entry.technique.name}
                              {entry.isPrereqCheck && <span style={{ marginLeft: 8, fontSize: 9, color: C.amber, background: `${C.amber}15`, padding: '1px 6px', borderRadius: 3, letterSpacing: 1 }}>PREREQ</span>}
                            </td>
                            <td style={{ padding: '9px 14px', color: C.textSec, maxWidth: 220 }}><span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.atomicTest?.name}</span></td>
                            <td style={{ padding: '9px 14px' }}><TacticBadge tacticId={entry.technique.tactic} small /></td>
                            <td style={{ padding: '9px 14px' }}>
                              <span style={{ color: entry.status === 'success' ? C.accent : C.red, fontWeight: 600, fontSize: 11 }}>
                                {entry.status === 'success' ? '✓ SUCCESS' : '✕ FAILED'}
                              </span>
                            </td>
                            <td style={{ padding: '9px 14px', color: C.textMuted }}>{entry.duration ? (entry.duration / 1000).toFixed(1) + 's' : '—'}</td>
                          </tr>
                          {expanded && hasOutput && (
                            <tr style={{ background: C.bg }}>
                              <td colSpan={7} style={{ padding: '0 0 14px 14px' }}>
                                <div style={{ display: 'flex', gap: 12, padding: '4px 14px 0 0' }}>
                                  {entry.stderr && entry.stderr.trim().length > 0 && (
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                      <div style={{ fontSize: 10, color: C.red, letterSpacing: 1, fontWeight: 700, marginBottom: 6, marginTop: 6 }}>STDERR</div>
                                      <pre style={{ margin: 0, padding: '10px 12px', background: `${C.red}10`, border: `1px solid ${C.red}30`, borderRadius: 5, fontSize: 11, color: C.text, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 240, overflowY: 'auto' }}>{entry.stderr}</pre>
                                    </div>
                                  )}
                                  {entry.stdout && entry.stdout.trim().length > 0 && (
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                      <div style={{ fontSize: 10, color: C.accent, letterSpacing: 1, fontWeight: 700, marginBottom: 6, marginTop: 6 }}>STDOUT</div>
                                      <pre style={{ margin: 0, padding: '10px 12px', background: `${C.accent}08`, border: `1px solid ${C.accent}30`, borderRadius: 5, fontSize: 11, color: C.text, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 240, overflowY: 'auto' }}>{entry.stdout}</pre>
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
