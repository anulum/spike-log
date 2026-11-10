# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — native distribution and selected record version correspondence

"""Check genuine metadata correspondence through the public record and CLI APIs."""

import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from local_scaffold.reports import validate_child
from tests.conftest import SOURCE, payload, source_python
from tests.test_provenance_reproduction import reproduction_root as reproduction_root
from tests.test_provenance_reproduction import source_cohort as source_cohort

WHEEL = "packageurl_python-0.17.5-py3-none-any.whl"
WHEEL_SHA256 = "f0e55452ab37b5c192c443de1458e3f3b4d8ac27f747df6e8c48adeab081d321"


@pytest.fixture
def older_wheel() -> Path:
    """Require the original immutable wheel prepared by the declared Make target."""
    wheel = SOURCE / ".tool-cache/wheelhouse" / WHEEL
    assert wheel.stat().st_size == 30544
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == WHEEL_SHA256
    return wheel


@pytest.mark.parametrize("native_case", ["installed", "older", "missing"])
def test_public_record_requires_matching_native_version(
    source_cohort: Path, older_wheel: Path, tmp_path: Path, native_case: str
) -> None:
    """Original archive metadata cannot be labelled as a different selected version."""
    program = """import hashlib,importlib.metadata,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.provenance_reproduction import package_record
from local_scaffold.provenance_sources import load
from local_scaffold.reports import Fault
root=Path(sys.argv[2])
baseline=json.loads((root/'dependency-provenance.json').read_bytes())
record=next(p for p in baseline['packages'] if p['name']=='packageurl-python')
sources=load(Path(sys.argv[3]))
if sys.argv[4]:
    sys.path.insert(0,sys.argv[4])
distribution=importlib.metadata.distribution('packageurl-python')
try:
    result=package_record(record,sources)
except Fault as error:
    print(json.dumps({'code':error.code,'location':error.location,'actual_version':distribution.version}))
    raise SystemExit(error.exit_code)
expected=dict(record,official_metadata_sha256=sources[record['name']][0])
assert result==expected
assert result['metadata_sha256']==hashlib.sha256(distribution.read_text('METADATA').encode()).hexdigest()
print(json.dumps({'record':result,'actual_version':distribution.version}))
"""
    before = older_wheel.read_bytes()
    provider = str(older_wheel) if native_case == "older" else ""
    if native_case == "missing":
        directory = tmp_path / "original-distribution"
        with zipfile.ZipFile(older_wheel) as archive:
            archive.extractall(directory)
        metadata = directory / "packageurl_python-0.17.5.dist-info/METADATA"
        metadata.rename(tmp_path / "retained-METADATA")
        provider = str(directory)
    result = subprocess.run(
        source_python(
            "-I",
            "-c",
            program,
            str(SOURCE / "tools"),
            str(SOURCE),
            str(source_cohort),
            provider,
        ),
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == (0 if native_case == "installed" else 2), (
        result.stdout,
        result.stderr,
    )
    assert not result.stderr
    observed = json.loads(result.stdout)
    if native_case != "installed":
        assert observed == {
            "code": (
                "source_identity_mismatch"
                if native_case == "older"
                else "dependency_alignment.wrong-producer"
            ),
            "location": "packageurl-python",
            "actual_version": "0.17.5" if native_case == "older" else None,
        }
    else:
        assert observed["record"]["version"] == observed["actual_version"] == "0.17.6"
    assert older_wheel.read_bytes() == before


def test_complete_cli_keeps_original_graph_refusal(
    reproduction_root: Path, source_cohort: Path, older_wheel: Path
) -> None:
    """The complete CLI retains its existing earlier refusal of duplicate native metadata."""
    program = """import sys
sys.path.insert(0,sys.argv[1])
sys.path.insert(0,sys.argv[2])
from local_scaffold.provenance_cli import main
raise SystemExit(main(sys.argv[3:]))
"""
    before = (reproduction_root / "dependency-provenance.json").read_bytes()
    result = subprocess.run(
        source_python(
            "-I",
            "-c",
            program,
            str(SOURCE / "tools"),
            str(older_wheel),
            "--root",
            str(reproduction_root),
            "--inputs",
            str(source_cohort),
            "--mode",
            "generate",
            "--output",
            ".tool-cache/candidate.json",
            "--json",
        ),
        capture_output=True,
        timeout=20,
    )
    response = validate_child(
        payload(result, 2), "provenance_reproduction", 2, expected_scope="provenance_candidate"
    )
    assert response["reasons"][0]["code"] == "dependency_alignment.wrong-producer"
    assert not (reproduction_root / ".tool-cache/candidate.json").exists()
    assert (reproduction_root / "dependency-provenance.json").read_bytes() == before


@pytest.mark.parametrize("cached", [False, True])
def test_actual_metadata_fixture_preparation(
    tmp_path: Path, older_wheel: Path, cached: bool
) -> None:
    """The narrow Make entry fetches genuine bytes or retains a verified cached archive."""
    root = tmp_path / "preparation"
    root.mkdir()
    shutil.copyfile(SOURCE / "Makefile", root / "Makefile")
    shutil.copytree(SOURCE / ".make", root / ".make")
    destination = root / ".tool-cache/wheelhouse" / WHEEL
    if cached:
        destination.parent.mkdir(parents=True)
        shutil.copyfile(older_wheel, destination)
    result = subprocess.run(
        ["make", "--no-print-directory", "prepare-provenance-identity-fixture"],
        cwd=root,
        capture_output=True,
        timeout=100,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert not result.stderr
    assert destination.read_bytes() == older_wheel.read_bytes()
