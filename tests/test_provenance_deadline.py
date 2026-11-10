# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual supervised capture budgets and the installed worker protocol."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

import pytest
from coverage import CoverageData

from local_scaffold.provenance_capture import capture
from local_scaffold.reports import Fault, Report
from tests.conftest import SOURCE, payload
from tests.test_provenance_reproduction import invoke, reproduction_root, source_cohort

__all__ = ["reproduction_root", "source_cohort"]


@pytest.mark.parametrize("value", ["0", "-1", "121", "nan", "inf", "not-a-duration"])
def test_invalid_capture_budget(reproduction_root: Path, value: str) -> None:
    """Invalid resource controls stop without creating a snapshot."""
    payload(
        invoke(
            reproduction_root,
            Path(".tool-cache/new-inputs"),
            "--mode",
            "capture",
            "--capture-seconds",
            value,
        ),
        4,
    )
    assert not (reproduction_root / ".tool-cache/new-inputs").exists()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--mode", "generate", "--output", "candidate.json", "--capture-seconds", "1"],
        ["--mode", "verify", "--capture-seconds", "1"],
        ["--mode", "capture", "--capture-seconds", ""],
        ["--mode", "capture", "--capture-seconds", "1", "--capture-seconds", "2"],
    ],
)
def test_capture_budget_invocation(reproduction_root: Path, arguments: list[str]) -> None:
    """Budget options are single, nonempty and restricted to capture."""
    payload(invoke(reproduction_root, Path(".tool-cache/new-inputs"), *arguments), 4)
    assert not (reproduction_root / ".tool-cache/new-inputs").exists()
    assert not (reproduction_root / "candidate.json").exists()


@pytest.mark.parametrize("value", [True, 0.0, -1.0, 121.0, float("nan"), float("inf")])
def test_public_budget_api(reproduction_root: Path, value: float) -> None:
    """The actual supervisor API rejects invalid budgets before native execution."""
    report = Report("provenance_reproduction", scope="provenance_inputs")
    with pytest.raises(Fault) as error:
        capture(reproduction_root, ".tool-cache/new-inputs", report, budget=value)
    assert error.value.exit_code == 4
    assert not (reproduction_root / ".tool-cache/new-inputs").exists()


def test_actual_small_capture_budget() -> None:
    """A finite small public budget cannot admit an unfinished full capture."""
    directory = Path(tempfile.mkdtemp(prefix="capture-budget-", dir=SOURCE / ".tool-cache"))
    name = str((directory / "inputs").relative_to(SOURCE))
    result = payload(
        invoke(SOURCE, Path(name), "--mode", "capture", "--capture-seconds", "0.01"), 3
    )
    assert cast(list[dict[str, object]], result["reasons"])[0]["code"] == "tool_timeout"
    assert not (directory / "inputs/inputs.json").exists()


def test_actual_make_budget_forwarding() -> None:
    """The maintained Make target forwards an invalid explicit budget to the real CLI."""
    directory = Path(tempfile.mkdtemp(prefix="make-capture-budget-", dir=SOURCE / ".tool-cache"))
    name = str((directory / "inputs").relative_to(SOURCE))
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "prepare-provenance-inputs",
            "PROVENANCE_INPUTS=" + name,
            "PROVENANCE_CAPTURE_SECONDS=0",
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2
    value = json.loads(result.stdout.splitlines()[-1])
    assert value["exit_code"] == 4 and value["status"] == "invalid"
    assert not (directory / "inputs").exists()


def test_genuine_missing_worker_is_unavailable(
    reproduction_root: Path, source_cohort: Path, tmp_path: Path
) -> None:
    """A real copied installation loses its owned worker and reports unavailable."""
    shutil.copytree(
        SOURCE / "tools", reproduction_root / "tools", ignore=shutil.ignore_patterns("__pycache__")
    )
    shutil.copytree(source_cohort, reproduction_root / ".tool-cache/inputs")
    aliases: dict[str, str] = {}
    identities: dict[str, str] = {}
    for source in sorted((reproduction_root / "tools").rglob("*.py")):
        target = SOURCE / "tools" / source.relative_to(reproduction_root / "tools")
        original = source.read_bytes()
        assert original == target.read_bytes()
        aliases[str(source)] = str(target)
        identities[str(source)] = hashlib.sha256(original).hexdigest()
    measured = tmp_path / "actual-copy-coverage"
    measured.mkdir()
    environment = os.environ.copy()
    environment["COVERAGE_FILE"] = str(measured / "data")
    script = reproduction_root / "tools/reproduce_dependency_provenance.py"
    arguments = [
        str(script),
        "--root",
        str(reproduction_root),
        "--inputs",
        ".tool-cache/inputs",
        "--mode",
        "capture",
        "--json",
    ]
    command = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        "--parallel-mode",
        "--branch",
        "--source",
        str(reproduction_root / "tools"),
        *arguments,
    ]
    payload(
        subprocess.run(command, cwd=SOURCE, env=environment, capture_output=True, timeout=30), 0
    )
    worker = reproduction_root / "tools/local_scaffold/provenance_capture_worker.py"
    before = worker.read_bytes()
    retained = tmp_path / "retained-worker.py"
    worker.rename(retained)
    result = payload(
        subprocess.run(command, cwd=SOURCE, env=environment, capture_output=True, timeout=30), 3
    )
    assert cast(list[dict[str, object]], result["reasons"])[0]["code"] == "tool_unavailable"
    assert retained.read_bytes() == before
    assert (SOURCE / "tools/local_scaffold/provenance_capture_worker.py").read_bytes() == before

    combined = subprocess.run(
        [sys.executable, "-m", "coverage", "combine", "--keep", str(measured)],
        cwd=SOURCE,
        env=environment,
        capture_output=True,
        timeout=30,
    )
    assert combined.returncode == 0, (combined.stdout, combined.stderr)
    actual = CoverageData(basename=str(measured / "data"))
    actual.read()
    assert actual.has_arcs() and set(actual.measured_files()).issubset(aliases)
    for source_name, target_name in aliases.items():
        assert hashlib.sha256(Path(target_name).read_bytes()).hexdigest() == identities[source_name]
    destination = Path(os.environ.get("COVERAGE_FILE", str(SOURCE / ".tool-cache/coverage/data")))
    destination.parent.mkdir(parents=True, exist_ok=True)
    canonical = CoverageData(basename=str(destination), suffix=True)
    canonical.update(actual, map_path=aliases.__getitem__)
    canonical.write()
    proof = {
        "source_sha256": identities,
        "source_aliases": aliases,
        "measured_source_files": sorted(actual.measured_files()),
        "actual_copy_data": str(measured / "data"),
        "canonical_path_data": canonical.data_filename(),
    }
    (tmp_path / "copied-installation-source-map.json").write_text(json.dumps(proof, indent=2))
