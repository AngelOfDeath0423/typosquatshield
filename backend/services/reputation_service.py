
from datetime import datetime, timezone
import math


def parse_timestamp(value):
    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        return timestamp.astimezone(timezone.utc)

    except (TypeError, ValueError):
        return None


def calculate_live_reputation(
    metadata,
    assessment_time=None,
):
    """
    Calculate live reputation indicators using
    currently retained PyPI release records.

    This is an approximation of historical training
    features, not an exact reconstruction.
    """

    if assessment_time is None:
        assessment_time = datetime.now(timezone.utc)

    if assessment_time.tzinfo is None:
        raise ValueError(
            "Assessment time must include a timezone."
        )

    assessment_time = assessment_time.astimezone(
        timezone.utc
    )

    release_history = metadata.get(
        "release_history"
    ) or []

    timestamps = []

    for release in release_history:
        timestamp = parse_timestamp(
            release.get("first_upload_time")
        )

        if (
            timestamp is not None
            and timestamp < assessment_time
        ):
            timestamps.append(timestamp)

    timestamps.sort()

    prior_count = len(timestamps)

    if prior_count:
        earliest = timestamps[0]
        previous = timestamps[-1]

        observed_age = (
            assessment_time - earliest
        ).total_seconds() / 86400

        days_since_previous = (
            assessment_time - previous
        ).total_seconds() / 86400

        prior_release_span = (
            previous - earliest
        ).total_seconds() / 86400

    else:
        observed_age = None
        days_since_previous = None
        prior_release_span = None

    return {
        "prior_release_count": prior_count,
        "has_prior_history": int(prior_count > 0),
        "observed_package_age_days": (
            round(observed_age, 6)
            if observed_age is not None
            else None
        ),
        "days_since_previous_release": (
            round(days_since_previous, 6)
            if days_since_previous is not None
            else None
        ),
        "prior_release_span_days": (
            round(prior_release_span, 6)
            if prior_release_span is not None
            else None
        ),
        "reputation_status": (
            "approximate_live_history"
            if prior_count
            else "no_observed_prior_history"
        ),
        "reputation_limitations": [
            "Release history uses currently retained PyPI files.",
            "Historical training records may have different coverage.",
            "Observed age is not verified package creation age.",
            "Release count is not a measure of package trust.",
        ],
    }


if __name__ == "__main__":
    example = {
        "release_history": [
            {
                "version": "0.1.0",
                "first_upload_time": (
                    "2023-01-01T10:00:00+00:00"
                ),
            },
            {
                "version": "0.2.0",
                "first_upload_time": (
                    "2024-01-01T10:00:00+00:00"
                ),
            },
        ]
    }

    result = calculate_live_reputation(
        example,
        assessment_time=datetime(
            2025, 1, 1,
            tzinfo=timezone.utc,
        ),
    )

    print("TYPOSQUATSHIELD - LIVE REPUTATION TEST")

    for key, value in result.items():
        print(f"{key}: {value}")

    assert result["prior_release_count"] == 2
    assert result["has_prior_history"] == 1
    assert result["observed_package_age_days"] > 0

    print("[SUCCESS] Live reputation test passed.")
