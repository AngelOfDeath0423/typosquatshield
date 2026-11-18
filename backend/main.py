
from pathlib import Path
from typing import Literal
import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend.services.pypi_service import fetch_pypi_metadata
from backend.services.ml_service import assess_with_ml
from backend.services.advisory_service import generate_advisory
from backend.services.stdlib_service import (
    get_standard_library_info,
)
from backend.services.static_analysis_service import (
    assess_static_package,
)

from backend.services.assessment_history_service import (
    save_assessment,
    list_assessments,
    get_assessment,
)


from scripts.typosquatting_similarity import (
    analyze_package,
    load_reference_names,
)


# --------------------------------------------------
# Configuration
# --------------------------------------------------

logger = logging.getLogger(__name__)

app = FastAPI(
    title="TyposquatShield API",
    description="Pre-installation PyPI package risk advisory system",
    version="0.4.0",
)

BASE = Path(__file__).resolve().parent.parent


# --------------------------------------------------
# Assessment history
# --------------------------------------------------

def record_assessment(result):
    """
    Save a completed assessment to the database.

    If database logging fails, the assessment result is
    returned unchanged.

    Database failures must not affect risk classification.
    """
    try:
        save_assessment(result)

    except Exception:
        logger.exception(
            "Assessment history could not be saved"
        )

    return result


# --------------------------------------------------
# Basic API endpoints
# --------------------------------------------------

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


# --------------------------------------------------
# Request model
# --------------------------------------------------

class AssessmentRequest(BaseModel):
    package_name: str = Field(
        min_length=1,
        max_length=214,
    )

    include_static_analysis: bool = False

    assessment_context: Literal[
        "auto",
        "stdlib",
        "pypi",
    ] = "auto"


# --------------------------------------------------
# Standard-library assessment response
# --------------------------------------------------

def standard_library_response(name, info):
    """
    Return an informational result for a Python
    standard-library module.

    This does not assess a separately published
    PyPI distribution with the same name.
    """
    reasons = [
        f"'{name}' is included in the Python standard library.",
        "You can normally import it without using pip.",
        (
            "A separate PyPI distribution may share this name. "
            "Select PyPI distribution assessment if you "
            "specifically intend to install that distribution."
        ),
    ]

    return {
        "package": name,
        "version": None,
        "metadata": None,
        "metadata_status": "not_applicable",
        "typosquatting": None,
        "assessment_context": "stdlib",
        "standard_library": info,
        "assessment_status": "standard_library",
        "ml_prediction": None,
        "reputation": None,
        "risk_level": "Not Applicable",
        "advisory_reasons": reasons,
        "reasons": reasons,
        "static_analysis": {
            "scan_status": "not_applicable",
            "artifact_filename": None,
            "features": None,
            "processed_python_files": 0,
            "limitations": [
                "No PyPI distribution was assessed.",
                "Standard-library module detection is informational.",
            ],
        },
    }


# --------------------------------------------------
# Main package assessment endpoint
# --------------------------------------------------

@app.post("/assess")
async def assess_package(request: AssessmentRequest):

    name = request.package_name.strip()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Package name cannot be empty.",
        )

    # --------------------------------------------------
    # 1. Standard-library detection
    # --------------------------------------------------

    stdlib_info = get_standard_library_info(name)

    # Explicit standard-library assessment.
    if request.assessment_context == "stdlib":

        if stdlib_info is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"'{name}' is not recognised as a standard-library "
                    "module by this Python interpreter."
                ),
            )

        result = standard_library_response(
            name,
            stdlib_info,
        )

        return record_assessment(result)

    # Automatic mode prioritises standard-library recognition.
    if (
        request.assessment_context == "auto"
        and stdlib_info is not None
    ):

        result = standard_library_response(
            name,
            stdlib_info,
        )

        return record_assessment(result)

    # --------------------------------------------------
    # 2. Typosquatting similarity analysis
    # --------------------------------------------------

    references = load_reference_names()

    typo_result = analyze_package(
        name,
        references,
    )

    # --------------------------------------------------
    # 3. Fetch PyPI metadata
    # --------------------------------------------------

    try:
        metadata = await fetch_pypi_metadata(name)

    except HTTPException as exc:

        if exc.status_code != 404:
            raise

        # Package does not exist on PyPI.
        # Generate a similarity-based advisory.
        advisory = generate_advisory(
            metadata_status="not_found",
            typo_result=typo_result,
        )

        result = {
            "package": name,
            "version": None,
            "metadata": None,
            "metadata_status": "not_found",
            "typosquatting": typo_result,
            "assessment_context": "pypi",
            "standard_library": stdlib_info,
            "assessment_status": "similarity_only",
            "ml_prediction": None,
            "static_analysis": {
                "scan_status": "not_scanned",
                "artifact_filename": None,
                "features": None,
                "processed_python_files": 0,
                "limitations": [
                    "Package was not found on PyPI.",
                    "No package archive was available to scan.",
                ],
            },
            **advisory,
            "reasons": advisory["advisory_reasons"],
        }

        return record_assessment(result)

    # --------------------------------------------------
    # 4. Machine learning assessment
    # --------------------------------------------------

    try:
        ml_result = assess_with_ml(
            metadata,
            typo_result=typo_result,
        )

    except (ValueError, KeyError, TypeError):

        logger.exception(
            "ML feature preparation failed"
        )

        raise HTTPException(
            status_code=503,
            detail="ML assessment is temporarily unavailable.",
        )

    # --------------------------------------------------
    # 5. Generate final risk advisory
    # --------------------------------------------------

    advisory = generate_advisory(
        metadata_status="available",
        typo_result=typo_result,
        metadata=metadata,
        ml_prediction=ml_result.get("ml_prediction"),
        reputation=ml_result.get("reputation"),
    )

    # --------------------------------------------------
    # 6. Optional static source inspection
    # --------------------------------------------------

    static_analysis = {
        "scan_status": "not_scanned",
        "artifact_filename": None,
        "features": None,
        "processed_python_files": 0,
        "limitations": [
            "Static analysis was not requested.",
        ],
    }

    if request.include_static_analysis:

        try:
            static_analysis = await assess_static_package(
                metadata["package_name"],
                metadata["version"],
            )

        except Exception:

            logger.exception(
                "Optional static analysis failed"
            )

            static_analysis = {
                "scan_status": "failed",
                "artifact_filename": None,
                "features": None,
                "processed_python_files": 0,
                "limitations": [
                    "Static analysis could not be completed.",
                    "A failed scan is not evidence of package safety.",
                ],
            }

    # --------------------------------------------------
    # 7. Build final assessment response
    # --------------------------------------------------

    result = {
        "package": metadata["package_name"],
        "version": metadata["version"],
        "metadata": metadata,
        "metadata_status": "available",
        "typosquatting": typo_result,
        "assessment_context": "pypi",
        "standard_library": stdlib_info,
        **ml_result,
        **advisory,
        "static_analysis": static_analysis,
        "reasons": advisory["advisory_reasons"],
    }

    # --------------------------------------------------
    # 8. Save assessment and return response
    # --------------------------------------------------

    return record_assessment(result)


# --------------------------------------------------
# Assessment history API
# --------------------------------------------------

@app.get("/assessments")
def get_assessment_history(
    limit: int = 50,
    offset: int = 0,
):
    """
    Retrieve recent assessment summaries.
    """
    if not 1 <= limit <= 200:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 200.",
        )

    if offset < 0:
        raise HTTPException(
            status_code=400,
            detail="Offset cannot be negative.",
        )

    try:
        records = list_assessments(
            limit=limit,
            offset=offset,
        )

    except Exception:
        logger.exception(
            "Failed to retrieve assessment history"
        )

        raise HTTPException(
            status_code=503,
            detail="Assessment history is temporarily unavailable.",
        )

    return {
        "count": len(records),
        "limit": limit,
        "offset": offset,
        "assessments": records,
    }


@app.get("/assessments/{assessment_id}")
def get_saved_assessment(assessment_id: int):
    """
    Retrieve a saved assessment and its complete result.
    """
    if assessment_id < 1:
        raise HTTPException(
            status_code=400,
            detail="Assessment ID must be positive.",
        )

    try:
        record = get_assessment(assessment_id)

    except Exception:
        logger.exception(
            "Failed to retrieve saved assessment"
        )

        raise HTTPException(
            status_code=503,
            detail="Assessment history is temporarily unavailable.",
        )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Assessment record not found.",
        )

    return record
