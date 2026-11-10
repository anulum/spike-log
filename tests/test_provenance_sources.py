# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check complete source identities through the real reconstruction CLI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import payload
from tests.test_provenance_reproduction import (
    invoke,
)
from tests.test_provenance_reproduction import (
    reproduction_root as reproduction_root,
)
from tests.test_provenance_reproduction import (
    source_cohort as source_cohort,
)


@pytest.mark.parametrize("change", ["short", "duplicate", "version", "digest", "python", "lock"])
def test_cohort_mismatch_refuses(reproduction_root: Path, source_cohort: Path, change: str) -> None:
    """Incomplete or inconsistent captured data cannot produce an accepted candidate."""
    path = source_cohort / "inputs.json"
    value = json.loads(path.read_bytes())
    if change == "short":
        value["packages"].pop()
    elif change == "duplicate":
        value["packages"][-1] = value["packages"][0]
    elif change == "version":
        value["packages"][0]["version"] = "0"
    elif change == "digest":
        value["packages"][0]["sha256"] = "0" * 64
    elif change == "python":
        value["python"] = "3.13.15"
    else:
        value["lock_sha256"] = "0" * 64
    path.write_text(json.dumps(value) + "\n")
    result = payload(
        invoke(
            reproduction_root,
            source_cohort,
            "--mode",
            "generate",
            "--output",
            ".tool-cache/candidate.json",
        ),
        2,
    )
    assert result["status"] == "refused"
    assert not (reproduction_root / ".tool-cache/candidate.json").exists()


@pytest.mark.parametrize("change", ["wrong-version", "missing-artifact", "artifact-size"])
def test_changed_registry_record_refuses(
    reproduction_root: Path, source_cohort: Path, change: str
) -> None:
    """A byte-bound response still needs the selected package/artifact semantics."""
    index_path = source_cohort / "inputs.json"
    index = json.loads(index_path.read_bytes())
    selected = index["packages"][0]
    path = source_cohort / selected["path"]
    response = json.loads(path.read_bytes())
    if change == "wrong-version":
        response["info"]["version"] = "0"
    elif change == "missing-artifact":
        response["urls"] = []
    else:
        baseline = json.loads((reproduction_root / "dependency-provenance.json").read_bytes())
        filename = baseline["packages"][0]["source_artifact"]["filename"]
        artifact = next(row for row in response["urls"] if row["filename"] == filename)
        artifact["size"] += 1
    path.write_text(json.dumps(response) + "\n")
    selected["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    index_path.write_text(json.dumps(index) + "\n")
    result = payload(
        invoke(
            reproduction_root,
            source_cohort,
            "--mode",
            "generate",
            "--output",
            ".tool-cache/candidate.json",
        ),
        2,
    )
    assert cast(list[dict[str, Json]], result["reasons"])[0]["code"] == "source_identity_mismatch"


def test_missing_response_is_unavailable(reproduction_root: Path, source_cohort: Path) -> None:
    """Absent source remains unavailable instead of using a network replacement."""
    index = json.loads((source_cohort / "inputs.json").read_bytes())
    (source_cohort / index["packages"][0]["path"]).unlink()
    result = payload(invoke(reproduction_root, source_cohort), 3)
    assert cast(list[dict[str, Json]], result["reasons"])[0]["code"] == "input_unavailable"


@pytest.mark.parametrize("change", ["record-value-type", "response-array", "artifact-digests"])
def test_invalid_cohort_shapes(reproduction_root: Path, source_cohort: Path, change: str) -> None:
    """Supported JSON shapes remain mandatory after their raw bytes are bound."""
    index_path = source_cohort / "inputs.json"
    index = json.loads(index_path.read_bytes())
    entry = index["packages"][0]
    if change == "record-value-type":
        entry["version"] = 1
    else:
        path = source_cohort / entry["path"]
        response = json.loads(path.read_bytes())
        if change == "response-array":
            response = []
        else:
            baseline = json.loads((reproduction_root / "dependency-provenance.json").read_bytes())
            filename = baseline["packages"][0]["source_artifact"]["filename"]
            artifact = next(row for row in response["urls"] if row["filename"] == filename)
            artifact["digests"] = []
        path.write_text(json.dumps(response) + "\n")
        entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    index_path.write_text(json.dumps(index) + "\n")
    result = payload(
        invoke(
            reproduction_root,
            source_cohort,
            "--mode",
            "generate",
            "--output",
            ".tool-cache/candidate.json",
        ),
        4,
    )
    assert cast(list[dict[str, Json]], result["reasons"])[0]["code"] == "configuration_invalid"
    assert not (reproduction_root / ".tool-cache/candidate.json").exists()
