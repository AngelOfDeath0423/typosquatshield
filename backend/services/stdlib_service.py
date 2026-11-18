
import sys

STDLIB_MODULES = getattr(
    sys,
    "stdlib_module_names",
    frozenset(),
)


def is_standard_library_name(package_name: str) -> bool:
    if not isinstance(package_name, str):
        return False

    return package_name.strip() in STDLIB_MODULES


def get_standard_library_info(package_name: str):
    if not is_standard_library_name(package_name):
        return None

    return {
        "module_name": package_name.strip(),
        "is_standard_library": True,
        "installation_required": False,
        "python_version": (
            f"{sys.version_info.major}.{sys.version_info.minor}"
        ),
        "message": (
            "This module is included with the current "
            "Python interpreter and normally does not "
            "require pip installation."
        ),
        "note": (
            "A separate distribution with the same name "
            "may exist on PyPI. This result describes "
            "the standard-library module, not that distribution."
        ),
    }
