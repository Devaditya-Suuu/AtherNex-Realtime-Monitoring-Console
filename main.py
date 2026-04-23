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
import zipfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
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


# ============================================================================
# ENDPOINTS
# ============================================================================
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

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
