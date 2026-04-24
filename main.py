"""
FastAPI Backend for Cybersecurity Anomaly Detection MVP.

This version supports a multi-file model bundle with artifacts such as:
- config.pkl
- scaler.pkl
- tokenizer_config.json
- tokenizer.json
- fusion_model.keras.zip
- text_model.pt.zip

It prefers the provided model directory and keeps a safe fallback path.
"""

import json
import logging
import os
import pickle
import sys
import time
import zipfile
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
import socketio
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ============================================================================
# PATHS / CONSTANTS
# ============================================================================
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_FEATURES = [
    "response_time_ms",
    "status_code",
    "cpu_usage",
    "memory_usage",
    "retry_count",
]


# ============================================================================
# TRAINING HELPER REQUIRED BY PICKLE UNPICKLING
# ============================================================================
def fillna_and_select(dataframe: pd.DataFrame) -> pd.DataFrame:
    """
    Training-time helper retained for pickle compatibility.

    Some older pickles reference this function under __main__, so we expose it
    before loading any serialized artifact.
    """
    if not isinstance(dataframe, pd.DataFrame):
        dataframe = pd.DataFrame(dataframe)

    selected = dataframe.reindex(columns=DEFAULT_FEATURES)
    return selected.fillna(0)


sys.modules["__main__"].fillna_and_select = fillna_and_select


@dataclass
class ModelArtifacts:
    model_dir: Optional[Path] = None
    config: dict[str, Any] | None = None
    numeric_columns: list[str] | None = None
    text_column: str = "message"
    scaler: Any = None
    tokenizer_config: dict[str, Any] | None = None
    tokenizer_json_meta: dict[str, Any] | None = None
    fusion_model_archive_files: list[str] | None = None
    text_model_archive_files: list[str] | None = None
    legacy_model: Any = None
    mode: str = "uninitialized"


artifacts = ModelArtifacts()


# ============================================================================
# RUNTIME SECURITY STATE
# ============================================================================
BLOCKED_SOURCES: set[str] = set()
SECURITY_EVENTS: deque[dict[str, Any]] = deque(maxlen=1200)
SOURCE_STATS: dict[str, dict[str, Any]] = defaultdict(
    lambda: {
        "window_start": time.time(),
        "requests_in_window": 0,
        "total_requests": 0,
        "failures": 0,
        "last_seen": time.time(),
        "last_risk": 0.0,
    }
)

USER_BASELINES: dict[str, dict[str, Any]] = {
    "alice": {
        "departments": {"engineering"},
        "location": "bangalore",
        "work_start": 9,
        "work_end": 18,
        "daily_downloads": 3,
    },
    "bob": {
        "departments": {"marketing"},
        "location": "mumbai",
        "work_start": 10,
        "work_end": 19,
        "daily_downloads": 5,
    },
    "carol": {
        "departments": {"finance"},
        "location": "delhi",
        "work_start": 8,
        "work_end": 17,
        "daily_downloads": 8,
    },
    "admin": {
        "departments": {"*"},
        "location": "bangalore",
        "work_start": 9,
        "work_end": 18,
        "daily_downloads": 10,
    },
}
SUSPENDED_ACCOUNTS: set[str] = set()
USER_ACCESS_HISTORY: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=40))

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")


def append_security_event(event_type: str, source: str, severity: str, message: str, **extra):
    SECURITY_EVENTS.append(
        {
            "timestamp": time.strftime("%H:%M:%S"),
            "epoch": time.time(),
            "event_type": event_type,
            "source": source,
            "severity": severity,
            "message": message,
            **extra,
        }
    )


def identify_source(request: Request) -> str:
    attacker_id = request.headers.get("x-attacker-id")
    if attacker_id:
        return attacker_id.strip()[:64]

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def is_suspicious_payload(request: Request) -> bool:
    sample = f"{request.url.path} {request.url.query}".lower()
    markers = ["union", "select", "drop", "--", "or 1=1", "sleep(", "benchmark(", "../"]
    return any(marker in sample for marker in markers)


def update_source_stats(source: str, response_status: int) -> dict[str, Any]:
    now = time.time()
    stats = SOURCE_STATS[source]
    if now - stats["window_start"] >= 60:
        stats["window_start"] = now
        stats["requests_in_window"] = 0

    stats["requests_in_window"] += 1
    stats["total_requests"] += 1
    stats["last_seen"] = now
    if response_status >= 400:
        stats["failures"] += 1
    return stats


def normalize_user(username: str) -> str:
    return username.strip().lower()


def normalize_department(department: str) -> str:
    return department.strip().lower()


def is_suspended_account(username: str) -> bool:
    return normalize_user(username) in SUSPENDED_ACCOUNTS


def requires_department_check(baseline_departments: set[str], department: str) -> bool:
    if "*" in baseline_departments:
        return False
    return normalize_department(department) not in baseline_departments


def build_insider_response(score: int) -> tuple[str, str]:
    if score >= 70:
        return "HIGH RISK", "SUSPEND ACCOUNT"
    if score >= 40:
        return "MEDIUM RISK", "ALERT SECURITY TEAM"
    return "LOW RISK", "MONITOR"


async def emit_insider_threat(payload: dict[str, Any]) -> None:
    await sio.emit("insider_threat", payload)


def score_insider_threat(username: str, activity: dict[str, Any]) -> dict[str, Any]:
    user = normalize_user(username)
    baseline = USER_BASELINES.get(user)
    if baseline is None:
        return {
            "username": user,
            "risk_score": 100,
            "level": "HIGH RISK",
            "action": "SUSPEND ACCOUNT",
            "anomalies": [f"Unknown user '{username}' attempted privileged internal operation"],
            "timestamp": time.strftime("%H:%M:%S"),
        }

    score = 0
    anomalies: list[str] = []

    login_hour = activity.get("hour")
    if login_hour is not None:
        if login_hour < baseline["work_start"] or login_hour >= baseline["work_end"]:
            score += 30
            anomalies.append(
                f"Login at {int(login_hour)}:00 - outside normal hours ({baseline['work_start']}:00-{baseline['work_end']}:00)"
            )

    login_location = activity.get("location")
    if login_location:
        normalized_location = login_location.strip().lower()
        if normalized_location != baseline["location"]:
            score += 35
            anomalies.append(
                f"Login from {login_location} - usual location is {baseline['location'].title()}"
            )

    department = activity.get("department")
    if department and requires_department_check(baseline["departments"], department):
        score += 40
        anomalies.append(
            f"Accessed {department} dept - not in authorized clearance"
        )

    file_count = activity.get("file_count")
    if file_count is not None:
        threshold = baseline["daily_downloads"] * 5
        if int(file_count) > threshold:
            score += 50
            anomalies.append(
                f"Downloaded {int(file_count)} files - daily average is {baseline['daily_downloads']}"
            )

    if activity.get("record_access"):
        now = time.time()
        history = USER_ACCESS_HISTORY[user]
        history.append({"department": normalize_department(department or "unknown"), "timestamp": now})
        while history and now - history[0]["timestamp"] > 120:
            history.popleft()
        distinct_departments = {entry["department"] for entry in history}
        if len(distinct_departments) >= 3:
            score += 25
            anomalies.append("Multiple department accesses detected within a short time window")

    level, action = build_insider_response(score)
    return {
        "username": user,
        "risk_score": score,
        "level": level,
        "action": action,
        "anomalies": anomalies,
        "timestamp": time.strftime("%H:%M:%S"),
    }


# ============================================================================
# MODEL LOADING
# ============================================================================
def discover_model_dir() -> Optional[Path]:
    candidates = [
        Path(os.getenv("MODEL_DIR", "")).expanduser(),
        BASE_DIR / "model",
        Path("/Users/devadityaborah/Downloads/model"),
    ]

    for candidate in candidates:
        if candidate and str(candidate) != "." and candidate.exists() and candidate.is_dir():
            if (candidate / "config.pkl").exists() and (candidate / "scaler.pkl").exists():
                return candidate
    return None


def try_load_legacy_model() -> Any:
    legacy_path = BASE_DIR / "model.pkl"
    if not legacy_path.exists():
        return None

    try:
        model = joblib.load(legacy_path)
        logger.info("Loaded legacy model from %s", legacy_path)
        logger.info("Legacy model type: %s", type(model).__name__)
        return model
    except Exception as exc:
        logger.warning("Legacy model load failed: %s", exc)
        return None


def load_artifacts() -> ModelArtifacts:
    bundle = ModelArtifacts()
    bundle.legacy_model = try_load_legacy_model()

    model_dir = discover_model_dir()
    if model_dir is None:
        if bundle.legacy_model is not None:
            bundle.mode = "legacy-joblib"
        else:
            bundle.mode = "missing-model"
        return bundle

    bundle.model_dir = model_dir

    try:
        with open(model_dir / "config.pkl", "rb") as handle:
            cfg = pickle.load(handle)
        bundle.config = cfg if isinstance(cfg, dict) else {}
        bundle.numeric_columns = bundle.config.get("numeric_columns", DEFAULT_FEATURES)
        bundle.text_column = bundle.config.get("text_column", "message")
    except Exception as exc:
        logger.warning("Failed to load config.pkl: %s", exc)
        bundle.config = {}
        bundle.numeric_columns = DEFAULT_FEATURES

    try:
        bundle.scaler = joblib.load(model_dir / "scaler.pkl")
        logger.info("Loaded scaler: %s", type(bundle.scaler).__name__)
    except Exception as exc:
        logger.warning("Failed to load scaler.pkl: %s", exc)
        bundle.scaler = None

    try:
        with open(model_dir / "tokenizer_config.json", "r", encoding="utf-8") as handle:
            bundle.tokenizer_config = json.load(handle)
    except Exception as exc:
        logger.warning("Failed to load tokenizer_config.json: %s", exc)

    try:
        with open(model_dir / "tokenizer.json", "r", encoding="utf-8") as handle:
            tok_meta = json.load(handle)
        # Keep only light metadata for runtime visibility.
        bundle.tokenizer_json_meta = {
            "version": tok_meta.get("version"),
            "has_model": "model" in tok_meta,
            "has_decoder": "decoder" in tok_meta,
        }
    except Exception as exc:
        logger.warning("Failed to load tokenizer.json: %s", exc)

    try:
        with zipfile.ZipFile(model_dir / "fusion_model.keras.zip", "r") as zf:
            bundle.fusion_model_archive_files = zf.namelist()[:20]
    except Exception as exc:
        logger.warning("Failed to inspect fusion_model.keras.zip: %s", exc)

    try:
        with zipfile.ZipFile(model_dir / "text_model.pt.zip", "r") as zf:
            bundle.text_model_archive_files = zf.namelist()[:20]
    except Exception as exc:
        logger.warning("Failed to inspect text_model.pt.zip: %s", exc)

    # MVP runtime mode: use scaler-driven anomaly scoring for stable deployment
    # without forcing heavy torch/tensorflow dependencies in hackathon setups.
    if bundle.scaler is not None:
        bundle.mode = "bundle-scaler-mvp"
    elif bundle.legacy_model is not None:
        bundle.mode = "legacy-joblib"
    else:
        bundle.mode = "missing-model"

    return bundle


artifacts = load_artifacts()


# ============================================================================
# FASTAPI APP
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 60)
    logger.info("Anomaly Detection API Starting")
    logger.info("Mode: %s", artifacts.mode)
    logger.info("Model dir: %s", artifacts.model_dir)
    logger.info("Numeric columns: %s", artifacts.numeric_columns or DEFAULT_FEATURES)
    logger.info("=" * 60)
    yield
    logger.info("API Shutting down...")


app = FastAPI(
    title="Anomaly Detection API",
    description="Cybersecurity anomaly detection MVP",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROTECTED_PREFIX = "/target"


@app.middleware("http")
async def threat_monitoring_middleware(request: Request, call_next):
    if not request.url.path.startswith(PROTECTED_PREFIX):
        return await call_next(request)

    source = identify_source(request)
    if source in BLOCKED_SOURCES:
        append_security_event(
            "blocked_request",
            source,
            "critical",
            f"Blocked source attempted {request.method} {request.url.path}",
            path=request.url.path,
        )
        return JSONResponse(status_code=403, content={"detail": "Source blocked by AegisAI"})

    started = time.perf_counter()
    response = await call_next(request)
    response_time_ms = max(1.0, (time.perf_counter() - started) * 1000.0)

    stats = update_source_stats(source, response.status_code)
    suspicious = is_suspicious_payload(request)

    cpu_estimate = min(100.0, 18.0 + stats["requests_in_window"] * 1.7 + (22 if suspicious else 0))
    memory_estimate = min(100.0, 30.0 + stats["requests_in_window"] * 1.1)
    retry_count = min(stats["failures"], 30)
    message = f"{request.method} {request.url.path} | rps_window={stats['requests_in_window']} | suspicious={suspicious}"

    assessment = evaluate_request_features(
        {
            "response_time_ms": response_time_ms,
            "cpu_usage": cpu_estimate,
            "memory_usage": memory_estimate,
            "retry_count": retry_count,
            "status_code": response.status_code,
            "message": message,
        }
    )
    stats["last_risk"] = assessment.risk_score

    severity_label = "normal"
    if assessment.status == "HIGH RISK":
        severity_label = "critical"
    elif assessment.status == "MEDIUM RISK":
        severity_label = "warning"

    append_security_event(
        "traffic",
        source,
        severity_label,
        f"{request.method} {request.url.path} -> {response.status_code} | risk={assessment.risk_score}",
        status=assessment.status,
        action=assessment.action,
        risk_score=assessment.risk_score,
        path=request.url.path,
        response_time_ms=round(response_time_ms, 2),
    )

    if assessment.status == "HIGH RISK":
        BLOCKED_SOURCES.add(source)
        append_security_event(
            "auto_block",
            source,
            "critical",
            f"AegisAI blocked source after high-risk pattern on {request.url.path}",
            status=assessment.status,
            risk_score=assessment.risk_score,
        )

    response.headers["x-aegis-status"] = assessment.status
    response.headers["x-aegis-risk"] = str(assessment.risk_score)
    response.headers["x-aegis-action"] = assessment.action
    return response


# ============================================================================
# SCHEMAS
# ============================================================================
class PredictionRequest(BaseModel):
    response_time_ms: float = Field(..., description="Response time in milliseconds")
    cpu_usage: float = Field(..., description="CPU usage percentage")
    memory_usage: float = Field(..., description="Memory usage percentage")
    retry_count: int = Field(..., description="Number of retries")
    status_code: int = Field(..., description="HTTP status code")
    message: Optional[str] = Field(default="", description="Optional log/message text")

    @field_validator("response_time_ms", "cpu_usage", "memory_usage")
    @classmethod
    def non_negative(cls, value):
        if value < 0:
            raise ValueError("Value cannot be negative")
        return value


class RiskAssessment(BaseModel):
    is_anomaly: bool
    risk_score: float
    status: str
    action: str
    confidence: float


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class InternalLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    location: str = Field(..., min_length=1, max_length=64)
    hour: int = Field(..., ge=0, le=23)


class InternalDownloadRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    department: str = Field(..., min_length=1, max_length=64)
    file_count: int = Field(..., ge=0)


class InternalAccessRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    department: str = Field(..., min_length=1, max_length=64)


# ============================================================================
# HELPERS
# ============================================================================
def to_input_frame(request: PredictionRequest, numeric_columns: list[str]) -> pd.DataFrame:
    row = {
        "response_time_ms": request.response_time_ms,
        "status_code": request.status_code,
        "cpu_usage": request.cpu_usage,
        "memory_usage": request.memory_usage,
        "retry_count": request.retry_count,
        "message": request.message or "",
    }

    # Keep order exactly as in training config.
    frame = pd.DataFrame([row])
    frame = frame.reindex(columns=numeric_columns)
    return frame


def score_from_scaler(frame: pd.DataFrame) -> tuple[int, float, float]:
    """
    MVP scoring path using fitted StandardScaler statistics.

    Returns:
    - prediction: -1 anomaly, 1 normal
    - risk_score: 0-100
    - confidence: 0-1
    """
    numeric = frame.astype(float)
    transformed = artifacts.scaler.transform(numeric)
    mean_abs_z = float(np.mean(np.abs(transformed)))

    # Calibrated threshold for MVP behavior: values near training distribution
    # stay SAFE/MEDIUM, strong outliers become HIGH RISK.
    anomaly_threshold = 1.8
    prediction = -1 if mean_abs_z >= anomaly_threshold else 1

    risk_score = max(0.0, min(100.0, (mean_abs_z / 3.0) * 100.0))
    confidence = max(0.0, min(1.0, mean_abs_z / 3.0))
    return prediction, risk_score, confidence


def score_from_legacy(frame: pd.DataFrame) -> tuple[int, float, float]:
    prediction = int(artifacts.legacy_model.predict(frame)[0])
    if hasattr(artifacts.legacy_model, "decision_function"):
        raw_score = float(artifacts.legacy_model.decision_function(frame)[0])
        risk_score = max(0.0, min(100.0, 50.0 - raw_score * 100.0))
        confidence = max(0.0, min(1.0, abs(raw_score) / (abs(raw_score) + 1.0)))
    else:
        risk_score = 80.0 if prediction == -1 else 20.0
        confidence = 0.6
    return prediction, risk_score, confidence


def classify(prediction: int, risk_score: float) -> tuple[str, str]:
    if prediction == -1:
        return "HIGH RISK", "BLOCK IP"
    if risk_score > 40:
        return "MEDIUM RISK", "ALERT"
    return "SAFE", "MONITOR"


def evaluate_request_features(features: dict[str, Any]) -> RiskAssessment:
    if artifacts.mode == "missing-model":
        return RiskAssessment(
            is_anomaly=False,
            risk_score=0.0,
            status="SAFE",
            action="MONITOR",
            confidence=0.0,
        )

    numeric_columns = artifacts.numeric_columns or DEFAULT_FEATURES
    prediction_request = PredictionRequest(**features)
    frame = to_input_frame(prediction_request, numeric_columns)

    if artifacts.mode == "bundle-scaler-mvp":
        prediction, risk_score, confidence = score_from_scaler(frame)
    else:
        prediction, risk_score, confidence = score_from_legacy(frame)

    status_text, action = classify(prediction, risk_score)
    return RiskAssessment(
        is_anomaly=prediction == -1,
        risk_score=round(risk_score, 2),
        status=status_text,
        action=action,
        confidence=round(confidence, 2),
    )


# ============================================================================
# ENDPOINTS
# ============================================================================
@app.post("/target/login", tags=["Target App"])
async def target_login(payload: LoginRequest):
    if payload.username == "admin" and payload.password == "aegis-safe-pass":
        return {"ok": True, "token": "demo-token"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/target/ping", tags=["Target App"])
async def target_ping():
    return {"ok": True, "message": "service responsive"}


@app.get("/target/search", tags=["Target App"])
async def target_search(q: str = ""):
    if len(q) > 300:
        raise HTTPException(status_code=400, detail="query too long")
    return {"query": q, "results": ["asset-1", "asset-2"]}


@app.get("/target/ports/{port}", tags=["Target App"])
async def target_port_probe(port: int):
    open_ports = {80, 443, 8080}
    if port in open_ports:
        return {"port": port, "state": "open"}
    raise HTTPException(status_code=404, detail="closed")


@app.post("/internal/login", tags=["Insider Threat"])
async def internal_login(payload: InternalLoginRequest):
    username = normalize_user(payload.username)
    if is_suspended_account(username):
        raise HTTPException(status_code=403, detail=f"Account '{username}' is suspended")

    result = score_insider_threat(
        username,
        {
            "hour": payload.hour,
            "location": payload.location,
        },
    )
    append_security_event(
        "insider_login",
        username,
        "critical" if result["level"] == "HIGH RISK" else "warning" if result["level"] == "MEDIUM RISK" else "normal",
        f"Internal login check -> {result['level']} ({result['risk_score']})",
        risk_score=result["risk_score"],
        level=result["level"],
        action=result["action"],
        anomalies=result["anomalies"],
    )
    await emit_insider_threat(result)

    if result["level"] == "HIGH RISK":
        SUSPENDED_ACCOUNTS.add(username)
        append_security_event(
            "insider_suspend",
            username,
            "critical",
            f"Account suspended after insider login anomaly (score={result['risk_score']})",
        )
        return JSONResponse(status_code=403, content=result)
    return result


@app.post("/internal/download", tags=["Insider Threat"])
async def internal_download(payload: InternalDownloadRequest):
    username = normalize_user(payload.username)
    if is_suspended_account(username):
        raise HTTPException(status_code=403, detail=f"Account '{username}' is suspended")

    result = score_insider_threat(
        username,
        {
            "department": payload.department,
            "file_count": payload.file_count,
        },
    )
    append_security_event(
        "insider_download",
        username,
        "critical" if result["level"] == "HIGH RISK" else "warning" if result["level"] == "MEDIUM RISK" else "normal",
        f"Internal download check -> {result['level']} ({result['risk_score']})",
        risk_score=result["risk_score"],
        level=result["level"],
        action=result["action"],
        anomalies=result["anomalies"],
    )
    await emit_insider_threat(result)

    if result["level"] == "HIGH RISK":
        SUSPENDED_ACCOUNTS.add(username)
        append_security_event(
            "insider_suspend",
            username,
            "critical",
            f"Account suspended after suspicious download volume (score={result['risk_score']})",
        )
        return JSONResponse(status_code=403, content=result)
    return result


@app.post("/internal/access", tags=["Insider Threat"])
async def internal_access(payload: InternalAccessRequest):
    username = normalize_user(payload.username)
    if is_suspended_account(username):
        raise HTTPException(status_code=403, detail=f"Account '{username}' is suspended")

    result = score_insider_threat(
        username,
        {
            "department": payload.department,
            "record_access": True,
        },
    )
    append_security_event(
        "insider_access",
        username,
        "critical" if result["level"] == "HIGH RISK" else "warning" if result["level"] == "MEDIUM RISK" else "normal",
        f"Internal access check -> {result['level']} ({result['risk_score']})",
        risk_score=result["risk_score"],
        level=result["level"],
        action=result["action"],
        anomalies=result["anomalies"],
    )
    await emit_insider_threat(result)

    if result["level"] == "HIGH RISK":
        SUSPENDED_ACCOUNTS.add(username)
        append_security_event(
            "insider_suspend",
            username,
            "critical",
            f"Account suspended after suspicious access behavior (score={result['risk_score']})",
        )
        return JSONResponse(status_code=403, content=result)
    return result


@app.get("/security/events", tags=["Security"])
async def security_events(limit: int = 120):
    clipped = max(1, min(limit, 600))
    events = list(SECURITY_EVENTS)[-clipped:]
    return {"count": len(events), "events": events}


@app.get("/security/blocklist", tags=["Security"])
async def security_blocklist():
    return {"blocked_sources": sorted(BLOCKED_SOURCES), "count": len(BLOCKED_SOURCES)}


@app.post("/security/unblock/{source}", tags=["Security"])
async def security_unblock_source(source: str):
    removed = source in BLOCKED_SOURCES
    BLOCKED_SOURCES.discard(source)
    if removed:
        append_security_event("manual_unblock", source, "warning", "Source unblocked by operator")
    return {"source": source, "unblocked": removed}


@app.post("/security/reset", tags=["Security"])
async def security_reset():
    BLOCKED_SOURCES.clear()
    SOURCE_STATS.clear()
    SECURITY_EVENTS.clear()
    SUSPENDED_ACCOUNTS.clear()
    USER_ACCESS_HISTORY.clear()
    append_security_event("reset", "operator", "warning", "Security state reset for new demo run")
    return {"ok": True, "message": "security state reset"}


@app.get("/security/overview", tags=["Security"])
async def security_overview():
    now = time.time()
    active_sources = []
    high_risk_recent = 0

    for source, stats in SOURCE_STATS.items():
        if now - stats["last_seen"] <= 600:
            active_sources.append(
                {
                    "source": source,
                    "requests_in_window": stats["requests_in_window"],
                    "total_requests": stats["total_requests"],
                    "failures": stats["failures"],
                    "last_risk": stats["last_risk"],
                }
            )
        if stats["last_risk"] >= 70:
            high_risk_recent += 1

    active_sources.sort(key=lambda row: row["requests_in_window"], reverse=True)

    return {
        "blocked_count": len(BLOCKED_SOURCES),
        "blocked_sources": sorted(BLOCKED_SOURCES),
        "suspended_account_count": len(SUSPENDED_ACCOUNTS),
        "suspended_accounts": sorted(SUSPENDED_ACCOUNTS),
        "event_count": len(SECURITY_EVENTS),
        "active_sources": active_sources[:10],
        "high_risk_sources": high_risk_recent,
    }


@app.get("/health", tags=["Health Check"])
async def health_check():
    return {
        "status": "healthy",
        "mode": artifacts.mode,
        "model_loaded": artifacts.mode != "missing-model",
        "model_dir": str(artifacts.model_dir) if artifacts.model_dir else None,
        "numeric_columns": artifacts.numeric_columns or DEFAULT_FEATURES,
    }


@app.get("/debug/model-info", tags=["Debug"])
async def model_info():
    return {
        "mode": artifacts.mode,
        "model_dir": str(artifacts.model_dir) if artifacts.model_dir else None,
        "config_keys": list((artifacts.config or {}).keys()),
        "numeric_columns": artifacts.numeric_columns or DEFAULT_FEATURES,
        "text_column": artifacts.text_column,
        "has_scaler": artifacts.scaler is not None,
        "has_tokenizer_config": artifacts.tokenizer_config is not None,
        "has_tokenizer_json": artifacts.tokenizer_json_meta is not None,
        "has_fusion_archive": artifacts.fusion_model_archive_files is not None,
        "has_text_archive": artifacts.text_model_archive_files is not None,
        "has_legacy_model": artifacts.legacy_model is not None,
    }


@app.post("/predict", response_model=RiskAssessment, tags=["Prediction"])
async def predict(request: PredictionRequest):
    if artifacts.mode == "missing-model":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No model artifacts available. Add model directory or model.pkl.",
        )

    try:
        numeric_columns = artifacts.numeric_columns or DEFAULT_FEATURES
        input_data = to_input_frame(request, numeric_columns)
        logger.info("Prediction input row: %s", input_data.iloc[0].to_dict())
        logger.info("Inference mode: %s", artifacts.mode)

        if artifacts.mode == "bundle-scaler-mvp":
            prediction, risk_score, confidence = score_from_scaler(input_data)
        else:
            prediction, risk_score, confidence = score_from_legacy(input_data)

        status_text, action = classify(prediction, risk_score)
        logger.info(
            "Prediction output -> pred=%s risk=%.2f status=%s action=%s conf=%.2f",
            prediction,
            risk_score,
            status_text,
            action,
            confidence,
        )

        return RiskAssessment(
            is_anomaly=prediction == -1,
            risk_score=round(risk_score, 2),
            status=status_text,
            action=action,
            confidence=round(confidence, 2),
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Prediction error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during prediction: {exc}",
        )


@app.get("/simulate-attack", response_model=RiskAssessment, tags=["Testing"])
async def simulate_attack():
    request = PredictionRequest(
        response_time_ms=5000,
        cpu_usage=95,
        memory_usage=98,
        retry_count=15,
        status_code=503,
        message="multiple failed login attempts from unknown IP",
    )
    return await predict(request)


if __name__ == "__main__":
    import uvicorn

    socket_app = socketio.ASGIApp(sio, other_asgi_app=app)
    uvicorn.run(socket_app, host="0.0.0.0", port=8001, log_level="info")
