"""
Blue Team Trainer - FastAPI Backend

Orchestrates Atomic Red Team execution on a Windows victim VM via WinRM.
Exposes endpoints consumed by the Blue Team Trainer frontend.

Run:
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from atomic_runner import AtomicRunner, WinRMError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("blueteam")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VICTIM_HOST = os.getenv("VICTIM_HOST")
VICTIM_USER = os.getenv("VICTIM_USER")
VICTIM_PASS = os.getenv("VICTIM_PASS")
WINRM_TRANSPORT = os.getenv("WINRM_TRANSPORT", "ntlm")
WINRM_PORT = int(os.getenv("WINRM_PORT", "5985"))
WINRM_TIMEOUT = int(os.getenv("WINRM_TIMEOUT", "300"))
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# ---------------------------------------------------------------------------
# Lifespan - initialise runner on startup, verify config
# ---------------------------------------------------------------------------

runner: Optional[AtomicRunner] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global runner
    missing = [
        k for k, v in {
            "VICTIM_HOST": VICTIM_HOST,
            "VICTIM_USER": VICTIM_USER,
            "VICTIM_PASS": VICTIM_PASS,
        }.items() if not v
    ]
    if missing:
        log.warning(
            "Missing required env vars: %s. Backend will start but "
            "detonation will fail until configured. Copy .env.example "
            "to .env and fill in the values.",
            ", ".join(missing),
        )
    else:
        runner = AtomicRunner(
            host=VICTIM_HOST,
            username=VICTIM_USER,
            password=VICTIM_PASS,
            transport=WINRM_TRANSPORT,
            port=WINRM_PORT,
            timeout=WINRM_TIMEOUT,
        )
        log.info("AtomicRunner initialised for victim %s", VICTIM_HOST)
    yield
    log.info("Shutting down")


app = FastAPI(
    title="Blue Team Trainer Backend",
    description="Orchestrates Atomic Red Team detonations on a Windows victim via WinRM",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DetonateRequest(BaseModel):
    technique_id: str = Field(..., example="T1059.001")
    test_id: str = Field(..., example="T1059.001-1")
    input_args: Optional[dict] = Field(default=None, description="Optional test arg overrides")


class DetonateResponse(BaseModel):
    success: bool
    technique_id: str
    test_id: str
    test_number: int
    duration_ms: int
    stdout: str
    stderr: str
    timestamp: str


class CleanupRequest(BaseModel):
    technique_id: str
    test_id: str


class HealthResponse(BaseModel):
    status: str
    victim_host: Optional[str]
    victim_reachable: bool
    configured: bool
    timestamp: str
    details: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_test_number(test_id: str) -> int:
    """Extract the trailing integer from a test_id like 'T1059.001-2' -> 2."""
    try:
        return int(test_id.rsplit("-", 1)[-1])
    except (ValueError, IndexError):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid test_id format: '{test_id}'. Expected 'TXXXX.YYY-N'.",
        )


def _require_runner() -> AtomicRunner:
    if runner is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Backend is not configured. Set VICTIM_HOST, VICTIM_USER, "
                "and VICTIM_PASS in the .env file and restart."
            ),
        )
    return runner


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/")
def root():
    return {
        "service": "blueteam-trainer-backend",
        "version": "1.0.0",
        "endpoints": ["/health", "/detonate", "/cleanup", "/check-prereqs"],
    }


@app.get("/health", response_model=HealthResponse)
def health():
    configured = runner is not None
    reachable = False
    details = None
    if configured:
        try:
            reachable = runner.test_connection()
            details = f"Connected to {VICTIM_HOST} via WinRM ({WINRM_TRANSPORT})"
        except WinRMError as e:
            details = f"WinRM connection failed: {e}"
        except Exception as e:
            details = f"Unexpected error: {e}"
    else:
        details = "Backend not configured - missing env vars"

    return HealthResponse(
        status="healthy" if reachable else "degraded",
        victim_host=VICTIM_HOST,
        victim_reachable=reachable,
        configured=configured,
        timestamp=datetime.utcnow().isoformat() + "Z",
        details=details,
    )


@app.post("/detonate", response_model=DetonateResponse)
def detonate(req: DetonateRequest):
    r = _require_runner()
    test_number = _parse_test_number(req.test_id)

    log.info("Detonating %s test #%d on %s", req.technique_id, test_number, VICTIM_HOST)

    try:
        result = r.execute_atomic(
            technique_id=req.technique_id,
            test_number=test_number,
            input_args=req.input_args or {},
        )
        log.info(
            "Detonation %s (%dms): success=%s",
            req.test_id, result.duration_ms, result.success,
        )
        return DetonateResponse(
            success=result.success,
            technique_id=req.technique_id,
            test_id=req.test_id,
            test_number=test_number,
            duration_ms=result.duration_ms,
            stdout=result.stdout,
            stderr=result.stderr,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )
    except WinRMError as e:
        log.error("WinRM error during detonation: %s", e)
        raise HTTPException(status_code=503, detail=f"WinRM error: {e}")
    except Exception as e:
        log.exception("Unexpected detonation failure")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cleanup")
def cleanup(req: CleanupRequest):
    r = _require_runner()
    test_number = _parse_test_number(req.test_id)
    log.info("Cleaning up %s test #%d", req.technique_id, test_number)
    try:
        result = r.cleanup_atomic(req.technique_id, test_number)
        return {
            "success": result.success,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except WinRMError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/check-prereqs/{technique_id}/{test_number}")
def check_prereqs(technique_id: str, test_number: int):
    r = _require_runner()
    log.info("Checking prereqs for %s test #%d", technique_id, test_number)
    try:
        result = r.check_prereqs(technique_id, test_number)
        return {
            "success": result.success,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("BIND_HOST", "0.0.0.0"),
        port=int(os.getenv("BIND_PORT", "8000")),
        reload=True,
    )
