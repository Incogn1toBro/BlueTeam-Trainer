"""
AtomicRunner - thin wrapper around pywinrm that drives Invoke-AtomicRedTeam
on a remote Windows victim.

The runner assumes the victim has:
  - WinRM enabled (HTTP on 5985 by default, or HTTPS on 5986)
  - Invoke-AtomicRedTeam module installed and on $env:PSModulePath
  - The 'atomics' folder populated (C:\\AtomicRedTeam\\atomics)

For HTTPS / Kerberos transport options, adjust the transport and port
parameters and ensure the client-side dependencies are installed
(e.g. `pywinrm[kerberos]`).
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Optional

import winrm
from winrm.exceptions import (
    WinRMError as LibWinRMError,
    WinRMTransportError,
    WinRMOperationTimeoutError,
)

log = logging.getLogger("blueteam.runner")


class WinRMError(Exception):
    """Raised when communication with the victim fails."""


@dataclass
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    duration_ms: int
    return_code: int = 0


# ---------------------------------------------------------------------------
# Output pattern matching
# ---------------------------------------------------------------------------

# Patterns that indicate a detonation genuinely failed, even if PowerShell
# reported exit 0. Atomic Red Team often swallows real failures into stdout.
DETONATION_FAILURE_PATTERNS: list[tuple[str, str]] = [
    # Network / DNS - common on isolated lab networks
    (r"(?i)remote name could not be resolved", "DNS resolution failed - victim has no internet access"),
    (r"(?i)unable to connect to the remote server", "Connection refused / network unreachable"),
    (r"(?i)the operation has timed out", "Network timeout"),
    (r"(?i)could not establish trust relationship for the SSL", "TLS handshake failed (cert issue or no internet)"),
    (r"(?i)no such host is known", "DNS resolution failed - victim has no internet access"),

    # Web request specific
    (r"(?i)Invoke-WebRequest.*?(404|403|500|502|503)", "HTTP error from external download"),
    (r"(?i)WebException", "Web request failed"),

    # Atomic framework explicit failures
    (r"ATOMIC_PRECHECK_FAILED", "Pre-flight check failed"),
    (r"ATOMIC_TEST_EXCEPTION", "Test threw an exception"),
    (r"(?i)Pre-requisites.*?not met", "Test prerequisites not met"),
    (r"(?i)This atomic test is not supported on", "Test not supported on this OS"),

    # Defender / AV
    (r"(?i)Operation did not complete successfully because the file contains a virus",
        "Defender blocked the test"),
    (r"(?i)This program is blocked by group policy", "Group policy blocked the test"),

    # Permissions
    (r"(?i)Access(Is)?Denied", "Access denied (run as admin?)"),
    (r"(?i)Requested registry access is not allowed", "Registry access denied"),
]

# Phrases Atomic prints when prerequisites are unsatisfied. CheckPrereqs
# always exits 0 even when prereqs fail - we detect failure by scanning
# for these patterns instead.
PREREQ_UNSATISFIED_PATTERNS: list[str] = [
    r"(?i)Prerequisites not met",
    r"(?i)must be installed",
    r"(?i)is not installed",
    r"(?i)does not exist",
    r"(?i)Try installing prereq",
]


def _extract_matching_lines(text: str, patterns: list[str], max_results: int = 5) -> list[str]:
    """Return the unique lines from `text` that contain any of the given
    regex patterns. Useful for surfacing context around matched output."""
    found: list[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end].strip()
            if line and line not in found:
                found.append(line)
                if len(found) >= max_results:
                    return found
    return found


# ---------------------------------------------------------------------------
# AtomicRunner
# ---------------------------------------------------------------------------


class AtomicRunner:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        transport: str = "ntlm",
        port: int = 5985,
        timeout: int = 300,
    ):
        self.host = host
        self.username = username
        self.password = password
        self.transport = transport
        self.port = port
        self.timeout = timeout
        scheme = "https" if port == 5986 else "http"
        self.endpoint = f"{scheme}://{host}:{port}/wsman"
        self._session: Optional[winrm.Session] = None

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _session_or_new(self) -> winrm.Session:
        if self._session is None:
            log.debug("Opening new WinRM session to %s", self.endpoint)
            self._session = winrm.Session(
                self.endpoint,
                auth=(self.username, self.password),
                transport=self.transport,
                server_cert_validation="ignore",
                read_timeout_sec=self.timeout + 10,
                operation_timeout_sec=self.timeout,
            )
        return self._session

    @staticmethod
    def _clean_stderr(raw: str) -> str:
        """Strip PowerShell CLIXML framing from stderr.

        WinRM-invoked PowerShell wraps verbose/progress/info records as a
        CLIXML document on the error stream. This is metadata, not actual
        errors - it confuses analysts who see big red 'STDERR' panels for
        healthy runs.

        We extract the human-readable error blocks if any, otherwise return
        empty. Genuine errors still come through this path.
        """
        if not raw:
            return ""

        if raw.lstrip().startswith("#< CLIXML"):
            # Pull out anything inside <S S="Error">...</S> tags - these are
            # the genuine error records embedded in the CLIXML.
            error_msgs = re.findall(
                r'<S S="Error">(.*?)</S>',
                raw,
                flags=re.DOTALL,
            )
            if error_msgs:
                cleaned = "\n".join(
                    msg.replace("_x000D__x000A_", "\n")
                       .replace("_x000A_", "\n")
                       .replace("&lt;", "<")
                       .replace("&gt;", ">")
                       .replace("&amp;", "&")
                       .replace("&quot;", '"')
                       .strip()
                    for msg in error_msgs
                )
                return cleaned.strip()
            # No <S S="Error"> blocks means stderr was just informational
            # (progress, verbose). Suppress entirely.
            return ""

        # Not CLIXML - return as-is (rare but possible)
        return raw

    def _run_ps(self, script: str) -> ExecutionResult:
        """Run a PowerShell script on the victim and return the result."""
        session = self._session_or_new()
        start = time.time()
        try:
            result = session.run_ps(script)
        except (LibWinRMError, WinRMTransportError, WinRMOperationTimeoutError) as e:
            self._session = None
            raise WinRMError(f"WinRM failure: {e}") from e
        except Exception as e:
            self._session = None
            raise WinRMError(f"Unexpected WinRM error: {e}") from e

        duration_ms = int((time.time() - start) * 1000)
        raw_stderr = result.std_err.decode("utf-8", errors="replace")
        cleaned_stderr = self._clean_stderr(raw_stderr)

        return ExecutionResult(
            success=result.status_code == 0,
            stdout=result.std_out.decode("utf-8", errors="replace"),
            stderr=cleaned_stderr,
            duration_ms=duration_ms,
            return_code=result.status_code,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def test_connection(self) -> bool:
        """Return True if a trivial PS command runs successfully on the victim."""
        result = self._run_ps("$env:COMPUTERNAME")
        if result.success:
            log.info("Victim hostname: %s", result.stdout.strip())
        return result.success

    def execute_atomic(
        self,
        technique_id: str,
        test_number: int,
        input_args: Optional[dict] = None,
    ) -> ExecutionResult:
        """Run a specific Atomic Red Team test on the victim.

        Success/failure detection works in three layers:
          1. PowerShell exit code (least reliable - Atomic often returns 0
             even on real failure)
          2. Sentinel strings in stdout (ATOMIC_TEST_COMPLETE / ATOMIC_PRECHECK_FAILED)
          3. Pattern matching against known failure indicators in output
             (DNS, HTTP errors, Defender blocks, etc.)
        """
        input_args_line = ""
        if input_args:
            pairs = "; ".join(
                f"'{k}'='{str(v).replace(chr(39), chr(39)*2)}'"
                for k, v in input_args.items()
            )
            input_args_line = f"-InputArgs @{{ {pairs} }}"

        script = f"""
$ErrorActionPreference = 'Continue'
$WarningPreference = 'Continue'
$logPath = 'C:\\AtomicRedTeam\\logs\\execution-{technique_id}-{test_number}.csv'

# Force-import the module - WinRM sessions don't always load profiles
$mod = Get-Module -ListAvailable Invoke-AtomicRedTeam | Select-Object -First 1
if (-not $mod) {{
    Write-Output "ATOMIC_PRECHECK_FAILED: Invoke-AtomicRedTeam module not found on victim."
    Write-Output "  Run the fix-atomic-install.ps1 script on the victim."
    exit 2
}}
Import-Module $mod.Name -Force

$atomicsPath = 'C:\\AtomicRedTeam\\atomics'
if (-not (Test-Path "$atomicsPath\\{technique_id}")) {{
    Write-Output "ATOMIC_PRECHECK_FAILED: No atomics for {technique_id} at $atomicsPath\\{technique_id}"
    Write-Output "  Run Install-AtomicsFolder on the victim to fetch them."
    exit 3
}}

Write-Output "=== Detonating {technique_id} test #{test_number} ==="
Write-Output "Module: $($mod.Path)"
Write-Output ""

try {{
    Invoke-AtomicTest {technique_id} -TestNumbers {test_number} {input_args_line} -PathToAtomicsFolder $atomicsPath -Force -ExecutionLogPath $logPath
    Write-Output ""
    Write-Output "ATOMIC_TEST_COMPLETE"
    exit 0
}} catch {{
    Write-Output ""
    Write-Output "ATOMIC_TEST_EXCEPTION: $($_.Exception.Message)"
    Write-Output "ScriptStackTrace: $($_.ScriptStackTrace)"
    exit 1
}}
""".strip()
        result = self._run_ps(script)
        combined = result.stdout + "\n" + result.stderr

        # Layer 3: pattern-match for known failure indicators first
        failure_reason: Optional[str] = None
        for pattern, reason in DETONATION_FAILURE_PATTERNS:
            if re.search(pattern, combined):
                failure_reason = reason
                break

        if failure_reason:
            result.success = False
            tag = f"[Detected failure] {failure_reason}"
            result.stderr = f"{tag}\n\n{result.stderr}" if result.stderr.strip() else tag
        elif "ATOMIC_TEST_COMPLETE" in result.stdout:
            result.success = True
        elif "ATOMIC_PRECHECK_FAILED" in result.stdout:
            result.success = False

        return result

    def cleanup_atomic(self, technique_id: str, test_number: int) -> ExecutionResult:
        """Run the cleanup commands defined by the atomic test."""
        script = f"""
$ErrorActionPreference = 'Continue'
$mod = Get-Module -ListAvailable Invoke-AtomicRedTeam | Select-Object -First 1
if (-not $mod) {{ Write-Output "Module not found"; exit 2 }}
Import-Module $mod.Name -Force
Invoke-AtomicTest {technique_id} -TestNumbers {test_number} -PathToAtomicsFolder 'C:\\AtomicRedTeam\\atomics' -Cleanup
Write-Output "CLEANUP_COMPLETE"
""".strip()
        result = self._run_ps(script)
        if "CLEANUP_COMPLETE" in result.stdout:
            result.success = True
        return result

    def check_prereqs(self, technique_id: str, test_number: int) -> ExecutionResult:
        """Check (and attempt to install) test prerequisites.

        Atomic Red Team always exits 0 from CheckPrereqs even when prereqs
        are unsatisfied - it just prints "Prerequisites not met" and stops.
        We detect that state by scanning the output for Atomic's actual
        failure phrases, so the UI does not falsely report success when
        a manual prerequisite (Microsoft Word, RDP enabled, AD environment,
        etc.) cannot be auto-installed.
        """
        script = f"""
$ErrorActionPreference = 'Continue'
$mod = Get-Module -ListAvailable Invoke-AtomicRedTeam | Select-Object -First 1
if (-not $mod) {{ Write-Output "Module not found"; exit 2 }}
Import-Module $mod.Name -Force
Invoke-AtomicTest {technique_id} -TestNumbers {test_number} -PathToAtomicsFolder 'C:\\AtomicRedTeam\\atomics' -CheckPrereqs -GetPrereqs
Write-Output "PREREQ_CHECK_COMPLETE"
""".strip()
        result = self._run_ps(script)
        combined = result.stdout + "\n" + result.stderr

        unsatisfied = _extract_matching_lines(combined, PREREQ_UNSATISFIED_PATTERNS)

        if unsatisfied:
            result.success = False
            summary = "Prerequisites not satisfied:\n  - " + "\n  - ".join(unsatisfied)
            result.stderr = (
                f"{summary}\n\n{result.stderr}" if result.stderr.strip() else summary
            )
        elif "PREREQ_CHECK_COMPLETE" in result.stdout:
            result.success = True
        else:
            result.success = False

        return result
