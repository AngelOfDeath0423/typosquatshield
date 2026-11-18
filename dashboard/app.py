import os
from pathlib import Path

import httpx
import streamlit as st


# --------------------------------------------------
# Configuration
# --------------------------------------------------

LOGO_PATH = Path(__file__).parent / "assets" / "logo.png"
API_BASE_URL = os.getenv("TPS_API_URL")

if not API_BASE_URL:
    API_BASE_URL = st.secrets.get(
        "TPS_API_URL",
        "http://127.0.0.1:8000",
    )

API_BASE_URL = API_BASE_URL.rstrip("/")

API_URL = f"{API_BASE_URL}/assess"

st.set_page_config(
    page_title="TyposquatShield | Package Assessment",
    page_icon=str(LOGO_PATH) if LOGO_PATH.is_file() else ":shield:",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# --------------------------------------------------
# Visual styling
# --------------------------------------------------

st.markdown(
    """
    <style>
    :root {
        --accent: #b69ae8;
        --muted: #9ca3af;
    }

    .block-container {
        max-width: 1120px;
        padding-top: 2.2rem;
        padding-bottom: 4rem;
    }

    [data-testid="stAppViewContainer"] {
        background: #101116;
    }

    h1, h2, h3 {
        letter-spacing: -0.035em;
    }

    h1 {
        font-weight: 700;
    }

    h2 {
        font-size: 1.4rem;
        font-weight: 650;
    }

    [data-testid="stForm"] {
        background: #191b23;
        border: 1px solid #30323d;
        border-radius: 14px;
        padding: 1.2rem 1.4rem;
    }

    div.stButton > button[kind="primary"],
    div.stFormSubmitButton > button[kind="primary"] {
        background: #9475d3;
        color: #ffffff;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        min-height: 44px;
    }

    div.stButton > button[kind="primary"]:hover,
    div.stFormSubmitButton > button[kind="primary"]:hover {
        background: #a58be0;
        color: #ffffff;
    }

    [data-testid="stMetric"] {
        background: #1a1c24;
        border: 1px solid #30323d;
        border-radius: 12px;
        padding: 1rem 1.15rem;
    }

    [data-testid="stMetricLabel"] {
        color: #a6a8b4;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.55rem;
        font-weight: 650;
        overflow-wrap: anywhere;
    }

    [data-testid="stExpander"] {
        background: #191b23;
        border: 1px solid #30323d;
        border-radius: 10px;
    }

    hr {
        border-color: #2b2d37;
    }

    .eyebrow {
        color: #b69ae8;
        font-size: 0.76rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        margin-bottom: 0.35rem;
    }

    .muted-copy {
        color: #a6a8b4;
        font-size: 0.92rem;
        line-height: 1.65;
    }

    .footer-note {
        color: #9093a0;
        font-size: 0.82rem;
        line-height: 1.7;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def readable_status(value):
    if not value:
        return "Unavailable"

    return str(value).replace("_", " ").capitalize()


def show_reasons(reasons):
    if not reasons:
        st.info("No explanation is available.")
        return

    for index, reason in enumerate(reasons, start=1):
        st.markdown(f"**{index}.** {reason}")


def show_suggestions(typo):
    suggestions = typo.get("suggestions") or []

    if not suggestions:
        st.caption("No close package-name suggestions were reported.")
        return

    rows = []

    for item in suggestions:
        if not isinstance(item, dict):
            continue

        name = (
            item.get("reference_package")
            or item.get("package")
            or item.get("name")
            or "Unknown"
        )

        distance = item.get("edit_distance")
        similarity = item.get("similarity")

        if isinstance(similarity, (int, float)):
            similarity_text = f"{similarity * 100:.1f}%"
        else:
            similarity_text = "Unavailable"

        rows.append({
            "Suggested package": name,
            "Edit distance": distance,
            "Name similarity": similarity_text,
        })

    if rows:
        st.dataframe(
            rows,
            use_container_width=True,
            hide_index=True,
        )
        st.caption(
            "Name similarity is not evidence that a package "
            "is malicious or trustworthy."
        )


def show_ml(result):
    status = result.get("assessment_status")
    prediction = result.get("ml_prediction")

    st.markdown("#### Machine learning assessment")
    st.caption(
        "The experimental model identifies patterns associated "
        "with the training labels. It does not verify malware."
    )

    st.write("**Assessment status:**", readable_status(status))

    if prediction is None:
        if status == "similarity_only":
            st.info(
                "This package was not found on PyPI. "
                "The advisory is based on name similarity; "
                "no ML prediction was produced."
            )
        elif status == "exact_reference_match_ml_not_applicable":
            st.info(
                "This package matches a curated reference name. "
                "The experimental ML prediction was not applied."
            )
        else:
            st.info(
                "No ML prediction is available for this assessment."
            )
        return

    if not isinstance(prediction, dict):
        st.write("Model output:", str(prediction))
        return

    # Show only fields actually returned by the model.
    for key, value in prediction.items():
        label = key.replace("_", " ").capitalize()

        if isinstance(value, (str, int, float, bool)):
            st.write(f"**{label}:** {value}")
        elif isinstance(value, dict):
            with st.expander(label):
                for subkey, subvalue in value.items():
                    st.write(
                        f"**{subkey.replace('_', ' ').capitalize()}:** "
                        f"{subvalue}"
                    )
        elif isinstance(value, list):
            with st.expander(label):
                for entry in value:
                    st.write("•", str(entry))


def show_static(result):
    static = result.get("static_analysis") or {}
    status = static.get("scan_status", "not_scanned")

    st.markdown("#### Static source inspection")

    if status == "complete":
        st.success("Archive inspection completed.")

        a, b = st.columns(2)

        with a:
            st.metric(
                "Python files inspected",
                static.get("processed_python_files", 0),
            )

        with b:
            st.metric(
                "Scan status",
                "Complete",
            )

        filename = static.get("artifact_filename")

        if filename:
            st.write("**Inspected archive:**", filename)

        features = static.get("features")

        if isinstance(features, dict) and features:
            st.markdown("**Observed indicators**")

            rows = []

            for key, value in features.items():
                if isinstance(value, (dict, list)):
                    continue

                rows.append({
                    "Indicator": key.replace("_", " ").capitalize(),
                    "Observed value": value,
                })

            if rows:
                st.dataframe(
                    rows,
                    use_container_width=True,
                    hide_index=True,
                )

            st.caption(
                "Observed indicators are descriptive signals. "
                "Their presence alone does not establish maliciousness."
            )

    elif status == "not_scanned":
        if result.get("metadata_status") == "not_found":
            st.info(
                "Inspection unavailable: the requested package "
                "was not found on PyPI, so there was no archive "
                "to inspect."
            )
        else:
            st.info(
                "Static analysis was not requested for this assessment."
            )
    else:
        st.warning(
            f"Static inspection could not be completed "
            f"({readable_status(status)}). "
            "An incomplete scan does not indicate safety."
        )

    limitations = static.get("limitations") or []

    if limitations:
        with st.expander("Inspection scope and limitations"):
            for item in limitations:
                st.write("•", item)
def display_standard_library_result(result):
    package = result.get("package", "Unknown")
    info = result.get("standard_library") or {}

    st.divider()

    st.markdown(
        '<div class="eyebrow">Python standard library</div>',
        unsafe_allow_html=True,
    )

    st.subheader(f"Results for {package}")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Module", package)

    with col2:
        st.metric("Installation", "Not required")

    st.success(
        f"**{package}** is included with Python "
        f"{info.get('python_version', '')}. "
        "You can normally import it without installing "
        "a separate PyPI package."
    )

    st.markdown("### Why no installation is needed")

    show_reasons(
        result.get("advisory_reasons")
        or result.get("reasons")
        or []
    )

    st.info(
        "A separate distribution with the same name may exist "
        "on PyPI. If you specifically intend to install it, "
        "choose **PyPI distribution** above and assess again."
    )

    st.caption(
        "This result identifies a standard-library module. "
        "It is not a malware or vulnerability scan."
    )

def display_assessment(result):
    if result.get("assessment_context") == "stdlib":
        display_standard_library_result(result)
        return

    package = result.get("package") or "Unknown"
    version = result.get("version") or "Not available"
    risk = result.get("risk_level") or "Unknown"

    st.divider()

    st.markdown(
        '<div class="eyebrow">Assessment overview</div>',
        unsafe_allow_html=True,
    )

    st.subheader(f"Results for {package}")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Package", package)

    with col2:
        st.metric("Version", version)

    with col3:
        st.metric("Risk advisory", risk)

    stdlib_info = result.get("standard_library")

    if (
        result.get("assessment_context") == "pypi"
        and isinstance(stdlib_info, dict)
        and stdlib_info.get("is_standard_library")
    ):
        st.info(
            f"**Python already includes a module named `{package}`.** "
            "This assessment concerns the separately published "
            "PyPI distribution, not the module supplied with Python. "
            "You normally do not need to install this distribution "
            "to import the standard-library module."
        )

    if risk == "High Risk":
        st.error(
            "**High Risk** — Review this package carefully "
            "before attempting installation."
        )
    elif risk == "Caution":
        st.warning(
            "**Caution** — Additional verification is recommended."
        )
    elif risk == "Low Risk":
        st.success(
            "**Low Risk** — No high-risk advisory was assigned. "
            "Package safety is not guaranteed."
        )
    else:
        st.info(
            "An advisory level could not be determined."
        )

    st.markdown("### Why this result?")

    reasons = (
        result.get("advisory_reasons")
        or result.get("reasons")
        or []
    )

    show_reasons(reasons)

    typo = result.get("typosquatting") or {}
    suggestions = typo.get("suggestions") or []

    if suggestions:
        st.markdown("### Check the intended package name")
        st.write(
            "The following curated package names are similar "
            "to the name you entered."
        )
        show_suggestions(typo)

    st.divider()

    st.markdown("### Detailed assessment")
    st.caption(
        "Explore the supporting information below. "
        "You don't need these details to understand the main advisory."
    )

    with st.expander("Machine learning assessment"):
        show_ml(result)

    with st.expander("Static source inspection"):
        show_static(result)

    metadata = result.get("metadata")

    if isinstance(metadata, dict):
        with st.expander("Package information"):
            fields = [
                ("Package name", "package_name"),
                ("Version", "version"),
                ("Summary", "summary"),
                ("Python requirement", "requires_python"),
                ("License", "license"),
                ("Release count", "release_count"),
            ]

            for label, key in fields:
                value = metadata.get(key)

                if value not in (None, "", [], {}):
                    st.write(f"**{label}:** {value}")

            st.caption(
                "Information is retrieved from PyPI metadata "
                "and may be incomplete or self-reported."
            )

    st.divider()

    st.markdown(
        '<div class="footer-note">'
        'TyposquatShield provides pre-installation risk advisories, '
        'not malware verification. Always review package identity, '
        'source, and suitability before installation.'
        '</div>',
        unsafe_allow_html=True,
    )


# --------------------------------------------------
# Header
# --------------------------------------------------

header_logo, header_title = st.columns(
    [0.8, 9],
    gap="small",
    vertical_alignment="center",
)

with header_logo:
    if LOGO_PATH.is_file():
        st.image(str(LOGO_PATH), width=76)
    else:
        st.markdown("🛡️")

with header_title:
    st.title("TyposquatShield")
    st.caption("PYTHON PACKAGE SECURITY")

st.markdown(
    '<div class="muted-copy">'
    'Assess PyPI packages before installation. Identify possible '
    'name impersonation, review reputation indicators, and '
    'understand the reasons behind each advisory.'
    '</div>',
    unsafe_allow_html=True,
)

st.write("")


# --------------------------------------------------
# Assessment form
# --------------------------------------------------

st.markdown("### New assessment")
st.caption(
    "Enter the exact package name you plan to install."
)

with st.form("assessment_form"):
    package_name = st.text_input(
        "Package name",
        placeholder="Try requests, numpy, or a suspected typo",
        max_chars=214,
    )

    assessment_mode = st.radio(
        "What would you like to check?",
        options=[
            "Automatic detection",
            "PyPI distribution",
        ],
        index=0,
        horizontal=True,
        help=(
            "Automatic detection recognises Python standard-library "
            "modules first. PyPI distribution explicitly assesses "
            "the separately published package."
        ),
    )


    include_static = st.checkbox(
        "Inspect package source files",
        value=False,
        help=(
            "Optional: downloads a verified package archive "
            "and inspects Python source without executing it. "
            "This may take longer than a standard assessment."
        ),
    )

    submitted = st.form_submit_button(
        "Assess package",
        type="primary",
        use_container_width=True,
    )


# --------------------------------------------------
# API communication
# --------------------------------------------------

if submitted:
    name = package_name.strip()

    # Clear previous results before a new assessment.
    st.session_state.pop("assessment", None)

    if not name:
        st.warning("Enter a package name to continue.")
    else:
        with st.spinner("Checking package information..."):
            try:
                with httpx.Client(timeout=120.0) as client:
                    response = client.post(
                        API_URL,
                        json={
                            "package_name": name,
                            "assessment_context": (
                                "pypi"
                                if assessment_mode == "PyPI distribution"
                                else "auto"
                            ),
                            "include_static_analysis": include_static,
                        },
                    )

                response.raise_for_status()

                st.session_state["assessment"] = response.json()

            except httpx.HTTPStatusError as exc:
                try:
                    detail = exc.response.json().get(
                        "detail",
                        "The assessment could not be completed.",
                    )
                except (ValueError, AttributeError):
                    detail = "The assessment could not be completed."

                st.error(f"Assessment failed: {detail}")

            except httpx.TimeoutException:
                st.error(
                    "The assessment took too long. "
                    "Please try again, or disable source inspection."
                )

            except httpx.RequestError:
                st.error(
                    "The assessment service is unavailable. "
                    "Check that the backend is running and try again."
                )

            except ValueError:
                st.error(
                    "The assessment service returned an invalid response."
                )


# --------------------------------------------------
# Results
# --------------------------------------------------

result = st.session_state.get("assessment")

if isinstance(result, dict):
    display_assessment(result)
else:
    st.divider()
    st.caption(
        "Enter a package name above to begin your assessment."
    )


# --------------------------------------------------
# Previous assessments (read-only API access)
# --------------------------------------------------

st.divider()
st.markdown("### Previous assessments")
st.caption(
    "Browse saved assessments without running another package check. "
    "History may include development and automated-test records."
)

history_controls = st.columns([2, 1, 1])
with history_controls[0]:
    history_search = st.text_input(
        "Search package name", key="history_search",
        placeholder="Search saved packages",
    )
with history_controls[1]:
    history_risk = st.selectbox(
        "Risk advisory",
        ["All levels", "Low Risk", "Caution", "High Risk", "Not Applicable"],
        key="history_risk",
    )
with history_controls[2]:
    history_limit = st.selectbox(
        "Recent records", [25, 50, 100, 200], index=1,
        key="history_limit",
    )

if st.button("Refresh history", key="refresh_history"):
    st.session_state.pop("history_records", None)

# Fetch only when first opening the page, changing the limit, or refreshing.
if (
    "history_records" not in st.session_state
    or st.session_state.get("history_loaded_limit") != history_limit
):
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.get(
                f"{API_BASE_URL}/assessments",
                params={"limit": history_limit, "offset": 0},
            )
            response.raise_for_status()
            payload = response.json()
        records = payload.get("assessments", [])
        if not isinstance(records, list):
            raise ValueError("Invalid history response")
        st.session_state["history_records"] = records
        st.session_state["history_loaded_limit"] = history_limit
    except (httpx.HTTPError, ValueError):
        st.warning(
            "Assessment history could not be loaded. "
            "Check that the FastAPI backend is running."
        )
        st.session_state["history_records"] = []
        st.session_state["history_loaded_limit"] = history_limit

history_records = st.session_state.get("history_records", [])
filtered_history = [
    record for record in history_records
    if history_search.casefold() in str(record.get("package_name") or "").casefold()
    and (
        history_risk == "All levels"
        or record.get("risk_level") == history_risk
    )
]

st.caption(
    f"Showing {len(filtered_history)} matching records from the "
    f"{len(history_records)} most recently retrieved assessments. "
    "Search and filters apply to retrieved records only."
)

if not filtered_history:
    st.info("No matching saved assessments in the retrieved history.")
else:
    for record in filtered_history:
        record_id = record.get("id")
        if not isinstance(record_id, int):
            continue
        package = record.get("package_name") or "Unknown"
        version = record.get("package_version") or "—"
        context = (
            "Standard library"
            if record.get("assessment_context") == "stdlib"
            else "PyPI"
        )
        risk = record.get("risk_level") or "Unknown"
        timestamp = str(record.get("created_at") or "Unknown time")
        cols = st.columns([2, 1, 1.25, 1.6, 1])
        with cols[0]:
            st.markdown(f"**{package}**")
            st.caption(f"Version: {version}")
        with cols[1]:
            st.write(context)
        with cols[2]:
            st.write(risk)
        with cols[3]:
            st.caption(timestamp)
        with cols[4]:
            is_expanded = (
                st.session_state.get("expanded_history_id") == record_id
            )
            button_label = "Hide details" if is_expanded else "View details"

            if st.button(button_label, key=f"view_saved_{record_id}"):
                if is_expanded:
                    st.session_state["expanded_history_id"] = None
                else:
                    st.session_state["expanded_history_id"] = record_id

        if st.session_state.get("expanded_history_id") == record_id:
            with st.container(border=True):
                # Cache only the selected saved record in the user's session.
                # No new assessment or database insert is performed.
                cached = st.session_state.get("expanded_history_record")
                if not isinstance(cached, dict) or cached.get("id") != record_id:
                    try:
                        with httpx.Client(timeout=15.0) as client:
                            detail_response = client.get(
                                f"{API_BASE_URL}/assessments/{record_id}"
                            )
                            detail_response.raise_for_status()
                            cached = detail_response.json()

                        if not isinstance(cached.get("result"), dict):
                            raise ValueError("Saved assessment has no result")

                        st.session_state["expanded_history_record"] = cached
                    except (httpx.HTTPError, ValueError, AttributeError):
                        cached = None
                        st.error("Could not retrieve the selected assessment.")

                if isinstance(cached, dict) and isinstance(cached.get("result"), dict):
                    st.caption(
                        f"Saved assessment #{record_id} · "
                        "Historical snapshot — no new scan performed"
                    )
                    display_assessment(cached["result"])

        st.divider()
