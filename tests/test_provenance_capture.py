# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise real complete source capture and unchanged offline reuse."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, payload, source_python
from tests.test_provenance_reproduction import invoke, reproduction_root, source_cohort

__all__ = ["reproduction_root", "source_cohort"]


def snapshot(directory: Path) -> dict[str, str]:
    """Read every actual snapshot file identity for independent retention checks."""
    return {
        str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def test_actual_capture_then_make_offline_reuse() -> None:
    """The public command captures all103real responses and Make reuses exact bytes."""
    workspace = Path(tempfile.mkdtemp(prefix="provenance-capture-", dir=SOURCE / ".tool-cache"))
    name = str((workspace / "inputs").relative_to(SOURCE))
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/reproduce_dependency_provenance.py"),
            "--root",
            str(SOURCE),
            "--inputs",
            name,
            "--mode",
            "capture",
            "--json",
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=150,
    )
    assert payload(result, 0)["scope"] == "provenance_inputs"
    index = json.loads((SOURCE / name / "inputs.json").read_bytes())
    baseline = json.loads((SOURCE / "dependency-provenance.json").read_bytes())
    assert {(p["name"], p["version"]) for p in index["packages"]} == {
        (p["name"], p["version"]) for p in baseline["packages"]
    }
    assert len(index["packages"]) == 103
    for entry in index["packages"]:
        data = (SOURCE / name / entry["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        response = json.loads(data)
        assert response["info"]["version"] == entry["version"]
    before = snapshot(SOURCE / name)
    prepared = subprocess.run(
        ["make", "--no-print-directory", "prepare-provenance-inputs", "PROVENANCE_INPUTS=" + name],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert prepared.returncode == 0 and not prepared.stderr, (prepared.stdout, prepared.stderr)
    assert json.loads(prepared.stdout.splitlines()[-1])["scope"] == "provenance_inputs"
    assert snapshot(SOURCE / name) == before
    payload(
        invoke(
            SOURCE,
            SOURCE / name,
            "--mode",
            "generate",
            "--output",
            str((workspace / "candidate.json").relative_to(SOURCE)),
        ),
        0,
    )
    candidate = json.loads((workspace / "candidate.json").read_bytes())
    assert len(candidate["packages"]) == 103
    assert sum(len(p["license_files"]) for p in candidate["packages"]) == 175
    expected = baseline
    digests = {p["name"]: p["sha256"] for p in index["packages"]}
    for record in expected["packages"]:
        record["official_metadata_sha256"] = digests[record["name"]]
    assert candidate == expected


def test_existing_complete_capture_stays_offline(
    reproduction_root: Path, source_cohort: Path
) -> None:
    """A genuine complete retained cohort is revalidated without replacement."""
    destination = reproduction_root / ".tool-cache/inputs"
    shutil.copytree(source_cohort, destination)
    before = snapshot(destination)
    result = payload(invoke(reproduction_root, Path(".tool-cache/inputs"), "--mode", "capture"), 0)
    assert result["scope"] == "provenance_inputs"
    assert snapshot(destination) == before


def test_incomplete_capture_is_retained(reproduction_root: Path) -> None:
    """An interrupted cohort with no complete index remains unavailable and intact."""
    directory = reproduction_root / ".tool-cache/inputs"
    directory.mkdir()
    (directory / "observed.json").write_text('{"retained": true}\n')
    before = snapshot(directory)
    result = payload(invoke(reproduction_root, Path(".tool-cache/inputs"), "--mode", "capture"), 3)
    assert cast(list[dict[str, Json]], result["reasons"])[0]["code"] == "input_unavailable"
    assert snapshot(directory) == before


@pytest.mark.parametrize("change", ["repository", "baseline"])
def test_capture_stops_at_baseline_mismatch(reproduction_root: Path, change: str) -> None:
    """Independent repository or byte drift stops before any capture directory exists."""
    if change == "repository":
        path = reproduction_root / "repository-domain.json"
        value = json.loads(path.read_bytes())
        value["repository_name"] = "SC-NEUROCORE"
        path.write_text(json.dumps(value) + "\n")
    else:
        path = reproduction_root / "dependency-provenance.json"
        path.write_bytes(path.read_bytes() + b"\n")
    payload(invoke(reproduction_root, Path(".tool-cache/inputs"), "--mode", "capture"), 2)
    assert not (reproduction_root / ".tool-cache/inputs").exists()


def test_capture_missing_parent_is_unavailable(reproduction_root: Path) -> None:
    """A nonexistent destination parent reports unavailable without starting acquisition."""
    result = payload(
        invoke(reproduction_root, Path(".tool-cache/missing-parent/inputs"), "--mode", "capture"),
        3,
    )
    assert cast(list[dict[str, Json]], result["reasons"])[0]["code"] == "input_unavailable"
    assert not (reproduction_root / ".tool-cache/missing-parent").exists()
