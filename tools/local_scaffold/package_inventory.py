# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Validate the reviewed native package exposure without building received code."""

from typing import Final

from .bindings import PYTHON_SUPPORTED_RANGE
from .reports import Report

BUILD: Final = {
    "requires": ["poetry-core==2.5.0"],
    "build-backend": "poetry.core.masonry.api",
}
PROJECT: Final = {
    "name": "spike-log",
    "version": "0.0.0.dev0",
    "description": "Explicit native event payload and container tooling",
    "readme": "README.md",
    "requires-python": PYTHON_SUPPORTED_RANGE,
    "license": "AGPL-3.0-or-later",
    "license-files": ["LICENSE", "LICENSES/*.txt", "NOTICE.md"],
    "dependencies": ["evidence-manifest-toolkit==0.0.0.dev0"],
    "authors": [{"name": "Miroslav Šotek", "email": "protoscience@anulum.li"}],
}
POETRY: Final = {
    "packages": [{"include": "spike_log", "from": "src"}],
    "include": [
        {"path": "src/spike_log/py.typed", "format": ["sdist", "wheel"]},
        {"path": "src/spike_log/py.typed.license", "format": ["sdist", "wheel"]},
    ],
}
PACKAGE_FILES: Final = frozenset(
    {
        "src/spike_log/__init__.py",
        "src/spike_log/dvs_columns.py",
        "src/spike_log/container_digests.py",
        "src/spike_log/logical_records.py",
        "src/spike_log/py.typed",
        "src/spike_log/py.typed.license",
    }
)


def package_matches(config: dict[str, object], files: list[str]) -> bool:
    """Compare actual configuration and package files with the reviewed population.

    Parameters
    ----------
    config : dict of str to object
        Native TOML data, never executable build configuration.
    files : list of str
        Actual bounded public-tree inventory from the caller's fixed reader.

    Returns
    -------
    bool
        True only for the exact builder, project, include declarations and
        complete reviewed source population. Extra dependencies stay refused.
    """
    tool = config.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    population = {name for name in files if name.startswith("src/spike_log/")}
    return (
        config.get("build-system") == BUILD
        and config.get("project") == PROJECT
        and poetry == POETRY
        and population == PACKAGE_FILES
    )


def verify_package(config: dict[str, object], files: list[str], report: Report) -> None:
    """Check the exact reviewed builder, metadata and source-package exposure.

    Parameters
    ----------
    config : dict of str to object
        Natively parsed TOML data; no received build hook is imported or run.
    files : list of str
        Bounded actual public inventory, not a received list of asserted files.
    report : Report
        Receives the existing private-packaged refusal for an unreviewed
        builder, project, package/include declaration or package file population.

    Notes
    -----
    This permits the actual enrolled payload package, not arbitrary project
    packaging. The complete wheel still requires independent build/content/
    install qualification. Private tracking and native source gates remain
    separate required operations.
    """
    if not package_matches(config, files):
        report.add("repository_inventory.private-packaged", "pyproject.toml")
