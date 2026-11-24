# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise supported payload documentation through the installed guard command."""

import subprocess
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, snapshots, source_python


def run_documentation(root: Path) -> subprocess.CompletedProcess[bytes]:
    """Run the real documentation CLI as a measured owned child."""
    return subprocess.run(
        source_python(
            "-B",
            str(SOURCE / "tools/check_documentation.py"),
            "--root",
            str(root),
            "--json",
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )


@pytest.mark.parametrize(
    "names",
    [
        "DvsEvent, DvsGeometry, decode_dvs_columns, encode_dvs_columns",
        "LogicalEvent, decode_logical_records, encode_logical_records",
        "DvsEvent as Event",
        "(DvsEvent, DvsGeometry)",
    ],
)
def test_actual_public_payload_imports_render(root: Path, names: str) -> None:
    """Render real supported names without claiming the unfinished operations."""
    page = root / "README.md"
    page.write_text(page.read_text() + "\n```python\nfrom spike_log import " + names + "\n```\n")
    before = snapshots(root)
    payload(run_documentation(root), 0)
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "names",
    [
        "record",
        "DvsEvent, record",
        "*",
        "(",
        "DvsEvent; x = 1",
        "",
        "DvsEvent = None",
        "()",
    ],
)
def test_unsupported_or_incomplete_imports_are_refused(root: Path, names: str) -> None:
    """Reject missing names, extra statements and malformed import examples."""
    page = root / "README.md"
    page.write_text(page.read_text() + "\n```python\nfrom spike_log import " + names + "\n```\n")
    report = payload(run_documentation(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict)
        and reason["code"] == "documentation.fake-api"
        and reason["location"] == "README.md"
        for reason in reasons
    )


@pytest.mark.parametrize("name", ["__init__.py", "dvs_columns.py", "logical_records.py"])
def test_documented_names_require_actual_source_identity(root: Path, name: str) -> None:
    """Refuse source drift instead of accepting a matching symbol spelling."""
    source = root / "src/spike_log" / name
    source.write_bytes(source.read_bytes() + b"\n")
    report = payload(run_documentation(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(r, dict) and r["code"] == "documentation.fake-api" for r in reasons)


@pytest.mark.parametrize("name", ["__init__.py", "dvs_columns.py", "logical_records.py"])
def test_missing_payload_source_is_unavailable(root: Path, name: str) -> None:
    """Keep absent source unavailable without fabricating an API acceptance."""
    (root / "src/spike_log" / name).unlink()
    report = payload(run_documentation(root), 3)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(r, dict) and r["code"] == "input_unavailable" for r in reasons)


@pytest.mark.parametrize("verb", ["record", "replay", "inspect", "verify", "slice"])
def test_payload_support_does_not_advertise_future_cli(root: Path, verb: str) -> None:
    """Retain refusal for every still-unimplemented complete domain command."""
    page = root / "README.md"
    page.write_text(page.read_text() + "\nspike-log " + verb + " is implemented\n")
    report = payload(run_documentation(root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(r, dict) and r["code"] == "documentation.fake-api" for r in reasons)
