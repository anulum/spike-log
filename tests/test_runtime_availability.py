# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual public orchestration with genuine incomplete tool producers."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from local_scaffold.reports import validate_child
from tests.conftest import SOURCE, payload, source_python
from tests.producer_environments import producer_environment


@pytest.fixture(scope="module")
def partial_tool_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Install only three verified genuine wheels in a real isolated interpreter."""
    directory = tmp_path_factory.mktemp("partial-actual-tool-producers")
    python = directory / "bin/python"
    records = [
        p
        for p in json.loads((SOURCE / "dependency-provenance.json").read_bytes())["packages"]
        if p["name"] in ("coverage", "packaging", "pyyaml")
    ]
    assert len(records) == 3
    wheels = []
    for record in records:
        artifact = record["source_artifact"]
        wheel = SOURCE / ".tool-cache/wheelhouse" / artifact["filename"]
        assert wheel.is_file() and not wheel.is_symlink()
        assert hashlib.sha256(wheel.read_bytes()).hexdigest() == artifact["sha256"]
        wheels.append(str(wheel))
    python = producer_environment(directory, [Path(wheel) for wheel in wheels])
    observed = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import hashlib,importlib.metadata,json;print(json.dumps([{'name':d.metadata['Name'].lower(),'version':d.version,'metadata_sha256':hashlib.sha256(d.read_text('METADATA').encode()).hexdigest()} for d in importlib.metadata.distributions()]))",
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    actual = json.loads(observed.stdout)
    assert len(actual) == 3
    assert {p["name"]: (p["version"], p["metadata_sha256"]) for p in actual} == {
        p["name"]: (p["version"], p["metadata_sha256"]) for p in records
    }
    return python


def test_actual_metadata_graph_drift(root: Path, partial_tool_python: Path) -> None:
    """A genuine sparse installed graph cannot pass the public metadata gate."""
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/check_repository_metadata.py"),
            "--root",
            str(root),
            "--json",
            executable=str(partial_tool_python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )
    report = validate_child(payload(result, 2), "repository_metadata", result.returncode)
    assert any(
        reason["code"] == "repository_metadata.installed-graph-drift"
        for reason in report["reasons"]
    )


@pytest.mark.parametrize("exhaust_diagnostics", [False, True])
def test_actual_partial_tool_preflight(
    root: Path, partial_tool_python: Path, exhaust_diagnostics: bool
) -> None:
    """The real public preflight preserves every actual or unrun required role."""
    if exhaust_diagnostics:
        for index in range(140):
            (root / ("unlicensed-" + str(index) + ".py")).write_text(
                '"""Unlicensed actual input."""\n'
            )
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/preflight.py"),
            "--root",
            str(root),
            "--json",
            executable=str(partial_tool_python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )
    report = validate_child(payload(result, 3), "preflight", result.returncode)
    checks = report["checks"]
    assert isinstance(checks, list) and len(checks) == 18
    assert all(isinstance(check, dict) for check in checks)
    assert any(check["status"] != "not_run" for check in checks)
    assert any(
        reason["code"] == "repository_metadata.installed-graph-drift"
        for reason in report["reasons"]
    )
    if exhaust_diagnostics:
        assert any(check["status"] == "not_run" for check in checks)
        assert len(report["reasons"]) == 256
    else:
        assert all(check["status"] != "not_run" for check in checks)
        assert any("tool_failed" in check["reason_codes"] for check in checks)


def test_actual_proc_availability_kernel_denial(root: Path) -> None:
    """An owned child receives real ENOENT from its kernel stat capability check."""
    program = """import ctypes,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.processes import run_process
from local_scaffold.reports import Fault
class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,4),Filter(0x06,0,0,0x50002),Filter(0x06,0,0,0x7fff0000))
program=Program(4,filters)
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0
assert libc.prctl(22,2,ctypes.byref(program),0,0)==0
assert not Path('/proc/self').is_dir()
try:
    run_process([sys.executable,'-c','raise AssertionError("Must not execute")'],Path(sys.argv[2]))
except Fault as fault:
    print(fault.code)
    sys.exit(fault.exit_code)
raise AssertionError('Unavailable kernel observation passed')
"""
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools"), str(root)),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 3 and result.stdout == b"tool_unavailable\n" and not result.stderr
