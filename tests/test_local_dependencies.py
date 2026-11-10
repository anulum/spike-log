# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise installed local producers and real source/cache refusal through public guards."""

from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from local_scaffold.local_dependencies import check_local_dependency
from local_scaffold.reports import Report
from tests.conftest import SOURCE, payload, run_guard, source_python
from tests.test_environment_failures import genuine_graph_lock, qualify_complete_graph
from tests.test_environment_failures import genuine_graph_python as genuine_graph_python


def local_records() -> list[dict[str, Json]]:
    """Select the two independently bound original provenance records."""
    value = json.loads((SOURCE / "dependency-provenance.json").read_text())
    return [
        cast(dict[str, Json], row)
        for row in value["packages"]
        if row["name"] in ("evidence-manifest-toolkit", "rfc8785")
    ]


def test_both_actual_local_producers_and_current_public_admission() -> None:
    """Require complete original wheels and installed bytes, then the real full public guard."""
    lock = (SOURCE / "requirements-dev.txt").read_text()
    for record in local_records():
        report = Report("dependency_alignment")
        check_local_dependency(record, lock, report)
        assert report.exit_code == 0
    payload(run_guard("dependency_alignment", SOURCE), 0)


@pytest.mark.parametrize("case", ("name", "kind", "wrong-kind", "wip", "namespace", "url", "lock"))
def test_original_local_record_disagreements_refuse(case: str) -> None:
    """Each adverse local identity or lock change retains the original refusal."""
    record = copy.deepcopy(local_records()[0])
    lock = (SOURCE / "requirements-dev.txt").read_text()
    source = cast(dict[str, Json], record["owner_source"])
    if case == "name":
        record["name"] = "other"
    elif case == "kind":
        record["source_kind"] = "registry"
    elif case == "wrong-kind":
        record["source_kind"] = "maintained_wheel"
    elif case == "wip":
        source["state"] = "owner_work_in_progress"
    elif case == "namespace":
        source["product_namespace"] = None
    elif case == "url":
        cast(dict[str, Json], record["source_artifact"])["url"] = "https://invalid.example/"
    else:
        artifact = cast(dict[str, Json], record["source_artifact"])
        lock = lock.replace(str(artifact["sha256"]), "0" * 64)
    report = Report("dependency_alignment")
    check_local_dependency(record, lock, report)
    assert report.exit_code == 2


@pytest.mark.parametrize("case", ("missing", "changed", "link"))
def test_actual_trusted_local_wheel_failure_refuses_and_recovers(case: str) -> None:
    """Alter only an owned cached entry; keep the shared original inode intact and restore it."""
    record = local_records()[0]
    artifact = cast(dict[str, Json], record["source_artifact"])
    wheel = SOURCE / ".tool-cache/environment-inputs" / cast(str, artifact["filename"])
    held = wheel.with_name(wheel.name + ".retained-negative")
    assert not held.exists()
    original = wheel.read_bytes()
    wheel.rename(held)
    try:
        if case == "changed":
            wheel.write_bytes(original[:-1])
        elif case == "link":
            wheel.symlink_to(held.name)
        payload(run_guard("dependency_alignment", SOURCE), 3 if case == "missing" else 2)
    finally:
        if os.path.lexists(wheel):
            wheel.unlink()
        held.rename(wheel)
    assert wheel.read_bytes() == original
    payload(run_guard("dependency_alignment", SOURCE), 0)


def test_genuine_local_distribution_absence_refuses(genuine_graph_python: Path) -> None:
    """Remove an actual owning distribution only in the complete native fixture and recover it."""
    prefix = genuine_graph_python.parents[1]
    metadata = (
        prefix / "lib/python3.13/site-packages/evidence_manifest_toolkit-0.0.0.dev0.dist-info"
    )
    retained = prefix / "original-common-dist-info"
    assert metadata.is_dir() and not retained.exists()
    program = """
import json,sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
from local_scaffold.local_dependencies import check_local_dependency
from local_scaffold.reports import Report,Fault
root=Path(sys.argv[2])
record=next(r for r in json.loads((root/"dependency-provenance.json").read_bytes())["packages"] if r["name"]=="evidence-manifest-toolkit")
try:
    check_local_dependency(record,(root/"requirements-dev.txt").read_text(),Report("dependency_alignment"))
except Fault as error:
    print(error.code)
    raise SystemExit(error.exit_code)
raise SystemExit(0)
"""
    with genuine_graph_lock(prefix.parent):
        qualify_complete_graph(genuine_graph_python)
        metadata.rename(retained)
        try:
            result = subprocess.run(
                source_python(
                    "-I",
                    "-B",
                    "-c",
                    program,
                    str(SOURCE / "tools"),
                    str(SOURCE),
                    executable=str(genuine_graph_python),
                ),
                cwd=SOURCE,
                capture_output=True,
                timeout=30,
            )
            assert (
                result.returncode == 2
                and result.stdout.strip() == b"dependency_alignment.wrong-producer"
            ), (result.stdout, result.stderr)
        finally:
            retained.rename(metadata)
        qualify_complete_graph(genuine_graph_python)
