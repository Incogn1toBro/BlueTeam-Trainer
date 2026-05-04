#!/usr/bin/env python3
"""
diagnose.py - Connectivity and readiness check for the Blue Team Trainer victim.

Run this from the backend folder with the venv activated:

    cd backend
    source .venv/bin/activate
    python diagnose.py

It walks through 6 checks in order, stopping at the first failure with a
clear remediation hint. Useful when tests are returning 'failed' with no
obvious cause.
"""
import os
import sys
from pathlib import Path

# Make sure we can find atomic_runner
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv

load_dotenv()

from atomic_runner import AtomicRunner, WinRMError  # noqa: E402

# ---- Pretty output ----
G = '\033[32m'  # green
R = '\033[31m'  # red
Y = '\033[33m'  # yellow
C_ = '\033[36m'  # cyan
D = '\033[2m'   # dim
RST = '\033[0m'

if not sys.stdout.isatty():
    G = R = Y = C_ = D = RST = ''


def step(n, total, label):
    print(f"\n{C_}[{n}/{total}]{RST} {label}")


def ok(msg):
    print(f"  {G}✓{RST} {msg}")


def fail(msg, hint=None):
    print(f"  {R}✕{RST} {msg}")
    if hint:
        print(f"     {Y}→{RST} {hint}")
    sys.exit(1)


def info(msg):
    print(f"    {D}{msg}{RST}")


# ---- Banner ----
print(f"""
{C_}╔══════════════════════════════════════════════════╗
║   Blue Team Trainer - Victim Diagnostics       ║
╚══════════════════════════════════════════════════╝{RST}
""")

# ---------------------------------------------------------------------------
# Step 1: env vars present
# ---------------------------------------------------------------------------
step(1, 6, "Checking backend configuration (.env)")

required = ['VICTIM_HOST', 'VICTIM_USER', 'VICTIM_PASS']
missing = [k for k in required if not os.getenv(k)]
if missing:
    fail(f"Missing env vars: {', '.join(missing)}",
         "Edit backend/.env and set the required values, then rerun.")
ok(f"VICTIM_HOST = {os.getenv('VICTIM_HOST')}")
ok(f"VICTIM_USER = {os.getenv('VICTIM_USER')}")
ok(f"VICTIM_PASS = {'*' * len(os.getenv('VICTIM_PASS'))}")
ok(f"WINRM_TRANSPORT = {os.getenv('WINRM_TRANSPORT', 'ntlm')}")
ok(f"WINRM_PORT = {os.getenv('WINRM_PORT', '5985')}")

# ---------------------------------------------------------------------------
# Step 2: WinRM connection
# ---------------------------------------------------------------------------
step(2, 6, "Testing WinRM connection to victim")

runner = AtomicRunner(
    host=os.getenv('VICTIM_HOST'),
    username=os.getenv('VICTIM_USER'),
    password=os.getenv('VICTIM_PASS'),
    transport=os.getenv('WINRM_TRANSPORT', 'ntlm'),
    port=int(os.getenv('WINRM_PORT', '5985')),
)

try:
    if not runner.test_connection():
        fail("Could not run a basic command on the victim",
             "Check WinRM is running on the victim: Get-Service WinRM")
    ok("WinRM responding")
except WinRMError as e:
    fail(f"WinRM error: {e}",
         "Common causes:\n"
         "       - Wrong password or username\n"
         "       - Firewall blocking port 5985 - test with: nc -zv <victim> 5985\n"
         "       - WinRM service not running on victim\n"
         "       - Host-only network not configured to allow this connection")

# ---------------------------------------------------------------------------
# Step 3: Victim hostname / OS
# ---------------------------------------------------------------------------
step(3, 6, "Gathering victim system info")
res = runner._run_ps(
    "[PSCustomObject]@{ "
    "Hostname=$env:COMPUTERNAME; "
    "User=$env:USERNAME; "
    "OS=(Get-CimInstance Win32_OperatingSystem).Caption; "
    "PSVersion=$PSVersionTable.PSVersion.ToString() } | Format-List"
)
print(D + res.stdout.strip() + RST)
ok("Got victim info")

# ---------------------------------------------------------------------------
# Step 4: Atomic Red Team module installed?
# ---------------------------------------------------------------------------
step(4, 6, "Checking Invoke-AtomicRedTeam module")

res = runner._run_ps(
    "$m = Get-Module -ListAvailable Invoke-AtomicRedTeam | Select-Object -First 1\n"
    "if ($m) { Write-Output \"FOUND $($m.Path)\" } else { Write-Output 'NOT_FOUND' }"
)
output = res.stdout.strip()
if 'NOT_FOUND' in output:
    fail("Invoke-AtomicRedTeam module not installed on victim",
         "On the victim, run: Install-AtomicRedTeam -getAtomics\n"
         "       Or re-run setup/victim-setup.ps1")
ok(output.replace('FOUND ', 'Module path: '))

# ---------------------------------------------------------------------------
# Step 5: Atomics folder populated?
# ---------------------------------------------------------------------------
step(5, 6, "Checking atomics folder is populated")

res = runner._run_ps(
    "$path = 'C:\\AtomicRedTeam\\atomics'\n"
    "if (Test-Path $path) {\n"
    "  $count = (Get-ChildItem $path -Directory | Measure-Object).Count\n"
    "  Write-Output \"$count technique folders at $path\"\n"
    "} else { Write-Output 'NOT_FOUND' }"
)
output = res.stdout.strip()
if 'NOT_FOUND' in output:
    fail("Atomics folder missing",
         "On victim: Install-AtomicRedTeam -getAtomics -Force")
ok(output)

# ---------------------------------------------------------------------------
# Step 6: Run a benign atomic test (T1082-1 systeminfo)
# ---------------------------------------------------------------------------
step(6, 6, "Running benign test T1082-1 (systeminfo enumeration)")
print(f"  {D}This is the simplest possible atomic test - if this fails, the issue")
print(f"  is environmental, not a Defender block.{RST}")

result = runner.execute_atomic('T1082', 1)

if result.success:
    ok("Test detonated successfully!")
    print(f"\n  {D}First few lines of output:{RST}")
    for line in result.stdout.split('\n')[:8]:
        print(f"    {line}")
    print(f"\n{G}{'='*52}\nALL CHECKS PASSED - Platform is ready.\n{'='*52}{RST}\n")
    print("If specific TTPs are still failing, the issue is likely:")
    print(f"  - {Y}Defender blocking the test{RST} (check Tamper Protection in GUI)")
    print(f"  - {Y}Test prerequisites missing{RST} (use 'Check Prereqs' in the UI)")
    print(f"  - {Y}Test legitimately needs admin/specific config{RST} (read the test YAML)")
    print()
else:
    print(f"  {R}✕{RST} Test failed.\n")
    print(f"  {Y}STDOUT:{RST}\n{D}{result.stdout}{RST}\n")
    print(f"  {Y}STDERR:{RST}\n{D}{result.stderr}{RST}\n")
    print(f"{R}If T1082-1 fails, something is wrong with the Atomic install.{RST}")
    print("Try on the victim:")
    print("  Import-Module Invoke-AtomicRedTeam -Force")
    print("  Invoke-AtomicTest T1082 -TestNumbers 1 -PathToAtomicsFolder C:\\AtomicRedTeam\\atomics")
    print()
    sys.exit(1)
