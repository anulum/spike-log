# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual payload ownership and typed-package admission through the CLI."""

import subprocess
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, snapshots, source_python


def run_provenance(root: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the real source gate as a measured owned child."""
    return subprocess.run(
        source_python(
            "-B",
            str(SOURCE / "tools/check_source_provenance.py"),
            "--root",
            str(root),
            "--json",
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )


def test_all_actual_project_headers_and_empty_typed_marker_pass(root: Path) -> None:
    """Accept the real module purposes and REUSE records without rewriting them."""
    before = snapshots(root)
    payload(run_provenance(root), 0)
    assert snapshots(root) == before


@pytest.mark.parametrize(
    ("name", "old", "new", "reason"),
    [
        ("src/spike_log/dvs_columns.py", "SPIKE-LOG —", "OTHER —", "wrong-notice"),
        ("src/spike_log/dvs_columns.py", "Concepts 1996", "Concepts 1997", "wrong-notice"),
        ("src/spike_log/dvs_columns.py", "AGPL-3.0-or-later", "MIT", "conflicting-spdx"),
        (
            "src/spike_log/dvs_columns.py",
            "canonical DVS event columns",
            "source and configuration provenance",
            "wrong-notice",
        ),
        (
            "src/spike_log/py.typed.license",
            "native payload API and typing",
            "unknown purpose",
            "wrong-notice",
        ),
        ("src/spike_log/py.typed.license", "AGPL-3.0-or-later", "MIT", "conflicting-spdx"),
        (
            "src/spike_log/py.typed.license",
            "SPDX-FileCopyrightText: 1996-2026 Miroslav Šotek <protoscience@anulum.li> (concepts)",
            "",
            "copyright-record",
        ),
        (
            "src/spike_log/py.typed.license",
            "SPDX-FileCopyrightText: 2020-2026 Miroslav Šotek <protoscience@anulum.li> (code)",
            "",
            "copyright-record",
        ),
    ],
)
def test_exact_project_ownership_is_still_required(
    root: Path, name: str, old: str, new: str, reason: str
) -> None:
    """Refuse changed owner, licence, module purpose or typed copyright records."""
    source = root / name
    original = source.read_text()
    assert old in original
    source.write_text(original.replace(old, new))
    report = payload(run_provenance(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(r, dict) and r["code"] == "source_provenance." + reason for r in reasons)


@pytest.mark.parametrize("fault", ["body", "sidecar"])
def test_typed_marker_is_exact_and_has_its_own_notice(root: Path, fault: str) -> None:
    """Reject a nonempty PEP561 marker or a missing adjacent ownership notice."""
    if fault == "body":
        (root / "src/spike_log/py.typed").write_bytes(b"partial\n")
    else:
        (root / "src/spike_log/py.typed.license").unlink()
    report = payload(run_provenance(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(r, dict)
        and r["code"] == "source_provenance.wrong-notice"
        and r["location"] == "src/spike_log/py.typed"
        for r in reasons
    )


def test_unknown_paths_do_not_inherit_known_module_purposes(root: Path) -> None:
    """A copied descriptive module header cannot authorise a different path."""
    (root / "src/spike_log/received.py").write_bytes(
        (root / "src/spike_log/dvs_columns.py").read_bytes()
    )
    report = payload(run_provenance(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(r, dict)
        and r["code"] == "source_provenance.wrong-notice"
        and r["location"] == "src/spike_log/received.py"
        for r in reasons
    )
