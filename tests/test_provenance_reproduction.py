# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise complete offline reconstruction through its actual public entry point."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, payload, source_python
from tests.test_provenance_local import INPUTS, OWNER


@pytest.fixture
def reproduction_root(tmp_path: Path) -> Path:
    """Copy every actual repository input consumed by reproduction."""
    root = tmp_path / "reproduction"
    for name in [
        "repository-domain.json",
        "schemas/repository-domain.schema.json",
        "requirements-dev.txt",
        "requirements-dev.in",
        "dependency-provenance.json",
    ]:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, target)
    (root / ".tool-cache").mkdir()
    return root


@pytest.fixture
def source_cohort(tmp_path: Path) -> Path:
    """Copy the complete genuine snapshot; missing preparation is a failure."""
    source = Path(
        os.environ.get("SPIKE_LOG_PROVENANCE_INPUTS", str(SOURCE / "vendor/provenance-inputs"))
    )
    index = json.loads((source / "inputs.json").read_bytes())
    assert len(index["packages"]) == len(
        json.loads((SOURCE / "dependency-provenance.json").read_bytes())["packages"]
    )
    target = tmp_path / "cohort"
    shutil.copytree(source, target)
    for entry in index["packages"]:
        assert hashlib.sha256((target / entry["path"]).read_bytes()).hexdigest() == entry["sha256"]
    return target


def invoke(root: Path, inputs: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    """Run the actual public CLI in the genuine locked interpreter.

    The local artifact and owner roots are passed unless the arguments name their own:
    a complete snapshot holds owner-source responses, which are read against them.
    """
    if "--artifacts" not in arguments and "--owner-source" not in arguments:
        arguments = (*arguments, "--artifacts", str(INPUTS), "--owner-source", str(OWNER))
    return subprocess.run(
        source_python(
            str(SOURCE / "tools/reproduce_dependency_provenance.py"),
            "--root",
            str(root),
            "--inputs",
            str(inputs),
            "--json",
            *arguments,
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )


def test_complete_generation_and_reference_comparison(
    reproduction_root: Path, source_cohort: Path
) -> None:
    """All records retain original fields except actual raw response identities."""
    before = (reproduction_root / "dependency-provenance.json").read_bytes()
    output = ".tool-cache/prospective.json"
    result = payload(
        invoke(reproduction_root, source_cohort, "--mode", "generate", "--output", output), 0
    )
    assert result["scope"] == "provenance_candidate"
    produced = (reproduction_root / output).read_bytes()
    generated = json.loads(produced)
    index = json.loads((source_cohort / "inputs.json").read_bytes())
    hashes = {entry["name"]: entry["sha256"] for entry in index["packages"]}
    expected = json.loads(before)
    for record in expected["packages"]:
        if "source_kind" not in record:
            record["official_metadata_sha256"] = hashes[record["name"]]
    assert generated == expected
    baseline = json.loads((SOURCE / "dependency-provenance.json").read_bytes())["packages"]
    assert len(generated["packages"]) == len(baseline)
    assert sum(len(p["license_files"]) for p in generated["packages"]) == sum(
        len(p["license_files"]) for p in baseline
    )
    assert (reproduction_root / "dependency-provenance.json").read_bytes() == before
    result = payload(invoke(reproduction_root, source_cohort, "--reference", output), 0)
    assert result["scope"] == "provenance_comparison"
    assert (reproduction_root / output).read_bytes() == produced


def test_reference_drift_is_reported(reproduction_root: Path, source_cohort: Path) -> None:
    """A changed candidate is refused without rewriting the reference."""
    output = ".tool-cache/prospective.json"
    payload(invoke(reproduction_root, source_cohort, "--mode", "generate", "--output", output), 0)
    target = reproduction_root / output
    value = json.loads(target.read_bytes())
    value["packages"][0]["metadata_sha256"] = "0" * 64
    target.write_text(json.dumps(value) + "\n")
    before = target.read_bytes()
    result = payload(invoke(reproduction_root, source_cohort, "--reference", output), 2)
    assert "source_identity_mismatch" in [
        row["code"] for row in cast(list[dict[str, Json]], result["reasons"])
    ]
    assert target.read_bytes() == before


def test_generation_preserves_existing_output(reproduction_root: Path, source_cohort: Path) -> None:
    """Generation retains a previously saved candidate unchanged."""
    target = reproduction_root / ".tool-cache/retained.json"
    target.write_bytes(b"retained candidate\n")
    result = payload(
        invoke(
            reproduction_root,
            source_cohort,
            "--mode",
            "generate",
            "--output",
            ".tool-cache/retained.json",
        ),
        2,
    )
    assert cast(list[dict[str, Json]], result["reasons"])[0]["code"] == "output_exists"
    assert target.read_bytes() == b"retained candidate\n"


def test_actual_make_generation_and_comparison(source_cohort: Path) -> None:
    """Both maintained Make targets exercise the genuine complete source cohort."""
    directory = Path(tempfile.mkdtemp(prefix="provenance-make-", dir=SOURCE / ".tool-cache"))
    output = str((directory / "candidate.json").relative_to(SOURCE))
    for target, setting in [
        ("provenance-generate", "PROVENANCE_OUTPUT=" + output),
        ("provenance-verify", "PROVENANCE_REFERENCE=" + output),
    ]:
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                target,
                "PROVENANCE_INPUTS=" + str(source_cohort),
                "PROVENANCE_ARTIFACTS=" + str(INPUTS),
                "PROVENANCE_OWNER_SOURCE=" + str(OWNER),
                setting,
            ],
            cwd=SOURCE,
            capture_output=True,
            timeout=30,
        )
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert not result.stderr
        response = json.loads(result.stdout.splitlines()[-1])
        assert response["exit_code"] == 0 and response["gate"] == "provenance_reproduction"
    assert len(json.loads((SOURCE / output).read_bytes())["packages"]) == len(
        json.loads((SOURCE / "dependency-provenance.json").read_bytes())["packages"]
    )
    assert {path.name for path in directory.iterdir()} == {"candidate.json"}
    shutil.rmtree(directory)


@pytest.mark.parametrize("change", ["repository-identity", "baseline-bytes"])
def test_independent_baseline_mismatch_stops_generation(
    reproduction_root: Path, source_cohort: Path, change: str
) -> None:
    """Metadata failure and exact baseline drift stop before candidate publication."""
    if change == "repository-identity":
        path = reproduction_root / "repository-domain.json"
        data = json.loads(path.read_bytes())
        data["repository_name"] = "SC-NEUROCORE"
        path.write_text(json.dumps(data) + "\n")
    else:
        path = reproduction_root / "dependency-provenance.json"
        path.write_bytes(path.read_bytes() + b"\n")
    before = path.read_bytes()
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
    assert path.read_bytes() == before
    assert not (reproduction_root / ".tool-cache/candidate.json").exists()


@pytest.mark.parametrize("mode", ["capture", "generate"])
@pytest.mark.parametrize("change", ["version", "remove", "additional"])
def test_direct_requirements_drift_stops_work(
    reproduction_root: Path, source_cohort: Path, mode: str, change: str
) -> None:
    """Changed, missing or extra direct dependencies refuse before any output appears."""
    path = reproduction_root / "requirements-dev.in"
    before = path.read_bytes()
    manifest = json.loads((reproduction_root / "dependency-provenance.json").read_bytes())
    package = next(p for p in manifest["packages"] if p["role"] == "direct")
    declaration = (package["name"] + "==" + package["version"]).encode()
    assert declaration in before
    if change == "version":
        data = before.replace(declaration, (package["name"] + "==0.0").encode())
    elif change == "remove":
        data = before.replace(declaration + b"\n", b"")
    else:
        data = before + b"additional-unlocked-tool==1.0\n"
    assert data != before
    path.write_bytes(data)
    inputs = source_cohort if mode == "generate" else Path(".tool-cache/new-inputs")
    arguments = ["--mode", mode]
    if mode == "generate":
        arguments += ["--output", ".tool-cache/candidate.json"]
    result = payload(invoke(reproduction_root, inputs, *arguments), 2)
    assert any(
        row["code"] == "source_identity_mismatch" and row["location"] == "requirements-dev.in"
        for row in cast(list[dict[str, Json]], result["reasons"])
    )
    assert not (reproduction_root / ".tool-cache/candidate.json").exists()
    assert not (reproduction_root / ".tool-cache/new-inputs").exists()
    assert path.read_bytes() == data
