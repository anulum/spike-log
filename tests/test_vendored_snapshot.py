# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance
"""Admit the vendored provenance snapshot only by the digests its index and the provenance pin."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, payload, run_guard

SNAPSHOT = "vendor/provenance-inputs"
REGISTRY = "registry/packaging.json"


def test_snapshot_index_pins_every_response_the_provenance_pins() -> None:
    """Each indexed response has its digest, which the provenance pins for that package."""
    index = cast(dict[str, Json], json.loads((SOURCE / SNAPSHOT / "inputs.json").read_bytes()))
    provenance = cast(
        dict[str, Json], json.loads((SOURCE / "dependency-provenance.json").read_bytes())
    )
    records = {
        cast(str, record["name"]): record
        for record in cast(list[dict[str, Json]], provenance["packages"])
    }
    entries = cast(list[dict[str, str]], index["packages"])
    assert index["input_schema"] == "spike_log.dependency-source-inputs.v2"
    assert (
        index["lock_sha256"]
        == hashlib.sha256((SOURCE / "requirements-dev.txt").read_bytes()).hexdigest()
    )
    assert sorted(entry["name"] for entry in entries) == sorted(records)
    for entry in entries:
        digest = hashlib.sha256((SOURCE / SNAPSHOT / entry["path"]).read_bytes()).hexdigest()
        record = records[entry["name"]]
        key = "source_input_sha256" if "source_kind" in record else "official_metadata_sha256"
        assert digest == entry["sha256"] == record[key], entry["path"]


@pytest.mark.parametrize("gate", ["repository_inventory", "source_provenance"])
@pytest.mark.parametrize("case", ["changed", "unlisted", "unknown-package", "provenance"])
def test_gates_refuse_an_unpinned_snapshot_response(root: Path, gate: str, case: str) -> None:
    """A snapshot response passes only when the index and the provenance pin its bytes.

    Parameters
    ----------
    root : Path
        Genuine isolated copy of the repository, whose snapshot passes both gates.
    gate : str
        Public guard that classifies snapshot responses.
    case : str
        A changed response byte, a response the index does not list, an index entry naming a
        package outside the provenance, or a provenance pin that no longer matches.
    """
    snapshot = root / SNAPSHOT
    name = REGISTRY
    if case == "changed":
        response = snapshot / REGISTRY
        response.write_bytes(response.read_bytes() + b"\n")
    elif case == "unlisted":
        name = "registry/unlisted.json"
        (snapshot / name).write_bytes((snapshot / REGISTRY).read_bytes())
    else:
        path = root / (
            "dependency-provenance.json" if case == "provenance" else SNAPSHOT + "/inputs.json"
        )
        value = cast(dict[str, Json], json.loads(path.read_bytes()))
        for entry in cast(list[dict[str, Json]], value["packages"]):
            if case == "provenance" and entry["name"] == "packaging":
                entry["official_metadata_sha256"] = "0" * 64
            if case == "unknown-package" and entry["path"] == REGISTRY:
                entry["name"] = "unknown-package"
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    code = (
        "source_identity_mismatch"
        if gate == "repository_inventory"
        else "source_provenance.third-party"
    )
    reasons = cast(list[dict[str, Json]], payload(run_guard(gate, root), 2)["reasons"])
    assert (code, SNAPSHOT + "/" + name) in [
        (reason["code"], reason["location"]) for reason in reasons
    ]
