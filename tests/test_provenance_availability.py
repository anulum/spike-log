# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual missing-dependency handling in a genuine isolated interpreter."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, payload, source_python
from tests.producer_environments import producer_environment


@pytest.fixture(scope="module")
def coverage_only_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Install only the genuine pinned Coverage wheel into an owned clean environment."""
    directory = tmp_path_factory.mktemp("provenance-coverage-only")
    environment = directory / "environment"
    wheel = SOURCE / (
        ".tool-cache/wheelhouse/coverage-7.16.2-cp313-cp313-"
        "manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl"
    )
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == (
        "4358b9c8c0125b460407f3017c6cce8156e904b32772c5630d27112f52bdbfe5"
    )
    python = producer_environment(environment, [wheel])
    return python


@pytest.mark.parametrize("mode", ["capture", "generate", "verify"])
def test_actual_missing_package_is_unavailable(
    coverage_only_python: Path, tmp_path: Path, mode: str
) -> None:
    """A real missing Packaging installation reports unavailable without producing output."""
    arguments = [
        str(SOURCE / "tools/reproduce_dependency_provenance.py"),
        "--root",
        str(tmp_path),
        "--inputs",
        ".",
        "--mode",
        mode,
        "--json",
    ]
    if mode == "generate":
        arguments += ["--output", "candidate.json"]
    result = payload(
        subprocess.run(
            source_python(*arguments, executable=str(coverage_only_python)),
            cwd=SOURCE,
            capture_output=True,
            timeout=10,
        ),
        3,
    )
    assert result["status"] == "unavailable"
    assert cast(list[dict[str, Json]], result["reasons"])[0]["code"] == "tool_unavailable"
    assert not (tmp_path / "candidate.json").exists()


def test_actual_missing_distribution_metadata(tmp_path: Path) -> None:
    """The public record API refuses genuine installed metadata absence and restores it."""
    environment = tmp_path / "record-environment"
    wheel_names = [
        (
            "coverage-7.16.2-cp313-cp313-manylinux1_x86_64."
            "manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl",
            "4358b9c8c0125b460407f3017c6cce8156e904b32772c5630d27112f52bdbfe5",
        ),
        (
            "packaging-26.3-py3-none-any.whl",
            "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c",
        ),
    ]
    wheels = []
    for name, digest in wheel_names:
        wheel = SOURCE / ".tool-cache/wheelhouse" / name
        assert hashlib.sha256(wheel.read_bytes()).hexdigest() == digest
        wheels.append(str(wheel))
    python = producer_environment(environment, [Path(wheel) for wheel in wheels])
    program = """import hashlib,importlib.metadata,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.provenance_reproduction import package_record
from local_scaffold.provenance_sources import load
from local_scaffold.reports import Fault
root=Path(sys.argv[2])
baseline=json.loads((root/"dependency-provenance.json").read_bytes())
record=next(p for p in baseline["packages"] if p["name"]=="coverage")
sources=load(root/".tool-cache/provenance-inputs")
distribution=importlib.metadata.distribution("coverage")
metadata=Path(str(distribution.locate_file("coverage-"+record["version"]+".dist-info/METADATA")))
before=metadata.read_bytes()
assert hashlib.sha256(before).hexdigest()==record["metadata_sha256"]
retained=Path(sys.argv[3])/"retained-METADATA"
metadata.rename(retained)
try:
    try:
        package_record(record,sources)
        result=0
    except Fault as fault:
        result=fault.exit_code
        print(json.dumps({"code":fault.code,"exit_code":fault.exit_code,"package":record["name"]}))
finally:
    retained.rename(metadata)
assert metadata.read_bytes()==before
raise SystemExit(result)
"""
    result = subprocess.run(
        source_python(
            "-c",
            program,
            str(SOURCE / "tools"),
            str(SOURCE),
            str(tmp_path),
            executable=str(python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2 and not result.stderr, (result.stdout, result.stderr)
    import json

    assert json.loads(result.stdout) == {
        "code": "dependency_alignment.wrong-producer",
        "exit_code": 2,
        "package": "coverage",
    }
