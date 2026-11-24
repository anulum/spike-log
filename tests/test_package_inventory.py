# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual package and source enrolment through the public inventory CLI."""

import subprocess
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, snapshots, source_python


def run_inventory(root: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the real primary producer as a measured owned child."""
    return subprocess.run(
        source_python(
            "-B",
            str(SOURCE / "tools/check_repository_inventory.py"),
            "--root",
            str(root),
            "--mode",
            "verify",
            "--json",
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )


def test_actual_native_package_is_enrolled_and_readonly(root: Path) -> None:
    """Accept actual src, typed marker and exact package configuration without rewriting."""
    before = snapshots(root)
    payload(run_inventory(root), 0)
    assert snapshots(root) == before


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("poetry-core==2.5.0", "poetry-core==2.4.0"),
        ("poetry.core.masonry.api", "received.builder"),
        ('name = "spike-log"', 'name = "unreviewed"'),
        ('license = "AGPL-3.0-or-later"', 'license = "MIT"'),
        ('readme = "README.md"', 'readme = "docs/internal/TODO.md"'),
        ('"LICENSES/*.txt"', '"docs/internal/**"'),
        ('include = "spike_log"', 'include = "local_scaffold"'),
        ('from = "src"', 'from = "."'),
        ('path = "src/spike_log/py.typed"', 'path = "docs/internal"'),
        ("[tool.poetry]", "[unreviewed.poetry]"),
    ],
)
def test_unreviewed_or_private_packaging_stays_refused(root: Path, old: str, new: str) -> None:
    """Keep native builder, licensing and exact public package exposure constraints."""
    config = root / "pyproject.toml"
    original = config.read_text()
    assert original.count(old) == 1
    config.write_text(original.replace(old, new))
    report = payload(run_inventory(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(r, dict) and r["code"] == "repository_inventory.private-packaged"
        for r in reasons
    )


def test_non_table_tooling_is_not_a_package_authority(root: Path) -> None:
    """A valid TOML scalar cannot supply the required reviewed package table."""
    config = root / "pyproject.toml"
    header = "\n".join(config.read_text().splitlines()[:7])
    config.write_text(header + '\n\ntool = "unreviewed"\n')
    report = payload(run_inventory(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(r, dict) and r["code"] == "repository_inventory.private-packaged"
        for r in reasons
    )


@pytest.mark.parametrize(
    "name",
    [
        "src/spike_log/extra.py",
        "src/spike_log/docs/internal/private.txt",
    ],
)
def test_unreviewed_package_file_population_is_refused(root: Path, name: str) -> None:
    """Known packaging cannot include arbitrary extra source or private working files."""
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    header = "\n".join(
        (SOURCE / "tools/check_repository_inventory.py").read_text().splitlines()[:7]
    )
    path.write_text(header + '\n\n"""Received unreviewed source data."""\n')
    report = payload(run_inventory(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(r, dict) and r["code"] == "repository_inventory.private-packaged"
        for r in reasons
    )


def test_other_source_namespaces_remain_unexamined(root: Path) -> None:
    """Enrolment of spike_log does not admit unrelated Python source roots."""
    path = root / "src/unreviewed.py"
    header = "\n".join(
        (SOURCE / "tools/check_repository_inventory.py").read_text().splitlines()[:7]
    )
    path.write_text(header + '\n\n"""Received unenrolled Python namespace."""\n')
    report = payload(run_inventory(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(r, dict)
        and r["code"] == "scan_incomplete"
        and r["location"] == "src/unreviewed.py"
        for r in reasons
    )


def test_only_the_exact_empty_typed_marker_is_enrolled(root: Path) -> None:
    """A nonempty PEP561 marker cannot escape source inspection by suffix."""
    (root / "src/spike_log/py.typed").write_bytes(b"partial\n")
    report = payload(run_inventory(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(r, dict)
        and r["code"] == "scan_incomplete"
        and r["location"] == "src/spike_log/py.typed"
        for r in reasons
    )
