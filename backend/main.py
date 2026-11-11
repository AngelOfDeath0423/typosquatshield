
from pathlib import Path
import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.services.pypi_service import fetch_pypi_metadata
from backend.services.ml_service import assess_with_ml
from backend.services.advisory_service import generate_advisory

from scripts.typosquatting_similarity import (
    analyze_package,
    load_reference_names,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="TyposquatShield API",
    description="Pre-installation PyPI package risk advisory system",
    version="0.3.0",
)

BASE = Path(__file__).resolve().parent.parent


@app.get("/")
def home():
    return {
        "system": "TyposquatShield",
        "status": "running",
        "description": "Pre-installation PyPI package risk advisory",
    }


@app.get("/health")
def health():
    return {
        "api_status": "healthy",
        "model_file_available": (
            BASE / "models/typosquatshield_baseline.joblib"
        ).is_file(),
        "model_metadata_available": (
            BASE / "models/typosquatshield_model_metadata.json"
        ).is_file(),
        "advisory_service_available": True,
    }


class AssessmentRequest(BaseModel):
    package_name: str = Field(
        min_length=1,
        max_length=214,
    )


@app.post("/assess")
async def assess_package(request: AssessmentRequest):
    name = request.package_name.strip()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Package name cannot be empty.",
        )

    references = load_reference_names()
    typo_result = analyze_package(name, references)

    try:
        metadata = await fetch_pypi_metadata(name)

    except HTTPException as exc:
        if exc.status_code != 404:
            raise

        advisory = generate_advisory(
            metadata_status="not_found",
            typo_result=typo_result,
        )

        return {
            "package": name,
            "version": None,
            "metadata": None,
            "metadata_status": "not_found",
            "typosquatting": typo_result,
            "assessment_status": "similarity_only",
            "ml_prediction": None,
            **advisory,
            "reasons": advisory["advisory_reasons"],
        }

    try:
        ml_result = assess_with_ml(
            metadata,
            typo_result=typo_result,
        )

    except (ValueError, KeyError, TypeError):
        logger.exception("ML feature preparation failed")

        raise HTTPException(
            status_code=503,
            detail="ML assessment is temporarily unavailable.",
        )

    advisory = generate_advisory(
        metadata_status="available",
        typo_result=typo_result,
        metadata=metadata,
        ml_prediction=ml_result.get("ml_prediction"),
        reputation=ml_result.get("reputation"),
    )

    return {
        "package": metadata["package_name"],
        "version": metadata["version"],
        "metadata": metadata,
        "metadata_status": "available",
        "typosquatting": typo_result,
        **ml_result,
        **advisory,
        "reasons": advisory["advisory_reasons"],
    }
