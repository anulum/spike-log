# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise the installed capture worker with complete real sources and refusals."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Literal, cast

import pytest

from local_scaffold.reports import Fault, validate_child
from tests.conftest import SOURCE, payload, source_python
from tests.test_provenance_availability import coverage_only_python
from tests.test_provenance_reproduction import invoke, reproduction_root

__all__ = ["coverage_only_python", "reproduction_root"]

WORKER_PROGRAM = (
    "import sys;sys.path.insert(0," + repr(str(SOURCE / "tools")) + ");"
    "from local_scaffold.provenance_capture_worker import main;"
    "raise SystemExit(main(sys.argv[1],sys.argv[2]))"
)


def test_native_worker_api_and_closed_scope(reproduction_root: Path) -> None:
    """The real installed worker captures103sources and admits only its explicit scope."""
    result = subprocess.run(
        source_python("-c", WORKER_PROGRAM, str(reproduction_root), ".tool-cache/inputs"),
        cwd=SOURCE,
        capture_output=True,
        timeout=150,
    )
    value = payload(result, 0)
    admitted = validate_child(
        value, "provenance_reproduction", 0, expected_scope="provenance_inputs"
    )
    assert admitted["scope"] == "provenance_inputs"
    with pytest.raises(Fault) as native_mismatch:
        validate_child(value, "provenance_reproduction", 2, expected_scope="provenance_inputs")
    assert native_mismatch.value.code == "child_status_mismatch"
    with pytest.raises(Fault):
        validate_child(value, "provenance_reproduction", 0)
    with pytest.raises(Fault):
        validate_child(value, "repository_metadata", 0, expected_scope="provenance_inputs")
    unsupported = cast(Literal["local_scaffold", "provenance_inputs"], "unsupported")
    with pytest.raises(Fault):
        validate_child(value, "provenance_reproduction", 0, expected_scope=unsupported)
    index = json.loads((reproduction_root / ".tool-cache/inputs/inputs.json").read_bytes())
    assert len(index["packages"]) == 103
    for entry in index["packages"]:
        data = (reproduction_root / ".tool-cache/inputs" / entry["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
    directory = reproduction_root / ".tool-cache/inputs"
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob("*")}
    payload(
        subprocess.run(
            source_python("-c", WORKER_PROGRAM, str(reproduction_root), ".tool-cache/inputs"),
            cwd=SOURCE,
            capture_output=True,
            timeout=30,
        ),
        0,
    )
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.rglob("*")}
    assert after == before
    response = payload(
        invoke(
            reproduction_root,
            Path(".tool-cache/inputs"),
            "--mode",
            "capture",
            "--capture-seconds",
            "120",
        ),
        0,
    )
    assert response["scope"] == "provenance_inputs"


@pytest.mark.parametrize(
    ("case", "expected", "code"),
    [
        ("repository", 2, "repository_metadata.wrong-identity"),
        ("baseline", 2, "source_identity_mismatch"),
        ("incomplete", 3, "input_unavailable"),
        ("missing-parent", 3, "input_unavailable"),
        ("missing-root", 3, "root_unavailable"),
        ("file-root", 3, "root_unavailable"),
    ],
)
def test_native_worker_input_refusals(
    reproduction_root: Path, case: str, expected: int, code: str
) -> None:
    """The installed worker rejects actual incomplete, unavailable and changed inputs."""
    root = reproduction_root
    name = ".tool-cache/inputs"
    retained: bytes | None = None
    target: Path | None = None
    if case == "repository":
        target = root / "repository-domain.json"
        value = json.loads(target.read_bytes())
        value["repository_name"] = "SC-NEUROCORE"
        target.write_text(json.dumps(value) + "\n")
        retained = target.read_bytes()
    elif case == "baseline":
        target = root / "dependency-provenance.json"
        target.write_bytes(target.read_bytes() + b"\n")
        retained = target.read_bytes()
    elif case == "incomplete":
        target = root / name / "retained.json"
        target.parent.mkdir()
        target.write_bytes(b'{"retained":true}\n')
        retained = target.read_bytes()
    elif case == "missing-parent":
        name = ".tool-cache/missing-parent/inputs"
    elif case == "missing-root":
        root = root / "missing"
    else:
        root = root / "repository-domain.json"
    result = payload(
        subprocess.run(
            source_python("-c", WORKER_PROGRAM, str(root), name),
            cwd=SOURCE,
            capture_output=True,
            timeout=30,
        ),
        expected,
    )
    assert result["scope"] == "provenance_inputs"
    assert code in [row["code"] for row in cast(list[dict[str, object]], result["reasons"])]
    if target is not None:
        assert target.read_bytes() == retained
    assert not (reproduction_root / name / "inputs.json").exists()


def test_native_worker_missing_dependency(coverage_only_python: Path, tmp_path: Path) -> None:
    """An actual interpreter without Packaging reports unavailable before publication."""
    result = payload(
        subprocess.run(
            source_python(
                "-c",
                WORKER_PROGRAM,
                str(tmp_path),
                "inputs",
                executable=str(coverage_only_python),
            ),
            cwd=SOURCE,
            capture_output=True,
            timeout=30,
        ),
        3,
    )
    assert [row["code"] for row in cast(list[dict[str, object]], result["reasons"])] == [
        "tool_unavailable"
    ]
    assert not (tmp_path / "inputs").exists()


def test_native_worker_unavailable_transport(reproduction_root: Path) -> None:
    """A genuinely unavailable configured proxy yields no complete source snapshot."""
    environment = os.environ.copy()
    environment.update(
        {
            "HTTPS_PROXY": "http://unavailable.invalid:80",
            "https_proxy": "http://unavailable.invalid:80",
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    result = payload(
        subprocess.run(
            source_python("-c", WORKER_PROGRAM, str(reproduction_root), ".tool-cache/inputs"),
            cwd=SOURCE,
            env=environment,
            capture_output=True,
            timeout=30,
        ),
        3,
    )
    assert [row["code"] for row in cast(list[dict[str, object]], result["reasons"])] == [
        "tool_unavailable"
    ]
    directory = reproduction_root / ".tool-cache/inputs"
    assert directory.is_dir() and not list(directory.iterdir())


def test_native_worker_user_interruption(reproduction_root: Path) -> None:
    """Actual user interruption during a full capture retains an unavailable outcome."""
    program = (
        "import sys,threading,os,signal;"
        "sys.path.insert(0," + repr(str(SOURCE / "tools")) + ");"
        "from local_scaffold.provenance_capture_worker import main;"
        "timer=threading.Timer(0.25,os.kill,args=(os.getpid(),signal.SIGINT));timer.start();"
        "\ntry: result=main(sys.argv[1],sys.argv[2])"
        "\nfinally: timer.cancel();timer.join()"
        "\nraise SystemExit(result)"
    )
    result = payload(
        subprocess.run(
            source_python("-c", program, str(reproduction_root), ".tool-cache/inputs"),
            cwd=SOURCE,
            capture_output=True,
            timeout=30,
        ),
        3,
    )
    assert [row["code"] for row in cast(list[dict[str, object]], result["reasons"])] == [
        "interrupted"
    ]
    assert not (reproduction_root / ".tool-cache/inputs/inputs.json").exists()


def test_native_worker_unencodable_root() -> None:
    """The public Python worker API contains an actual filesystem encoding failure."""
    program = (
        "import sys;sys.path.insert(0," + repr(str(SOURCE / "tools")) + ");"
        "from local_scaffold.provenance_capture_worker import main;"
        "raise SystemExit(main(chr(0xD800),'inputs'))"
    )
    result = payload(
        subprocess.run(source_python("-c", program), cwd=SOURCE, capture_output=True, timeout=30),
        2,
    )
    assert [row["code"] for row in cast(list[dict[str, object]], result["reasons"])] == [
        "unexpected_fault"
    ]


def test_worker_bounded_diagnostics(reproduction_root: Path) -> None:
    """The real worker retains a complete bounded refusal for excess input findings."""
    path = reproduction_root / "repository-domain.json"
    metadata = json.loads(path.read_bytes())
    metadata["capabilities"] = ["ARCH" + "-CASE-" + str(i) for i in range(300)]
    path.write_text(json.dumps(metadata) + "\n")
    before = path.read_bytes()
    result = payload(
        subprocess.run(
            source_python("-c", WORKER_PROGRAM, str(reproduction_root), ".tool-cache/inputs"),
            cwd=SOURCE,
            capture_output=True,
            timeout=30,
        ),
        2,
    )
    reasons = cast(list[dict[str, object]], result["reasons"])
    assert len(reasons) == 256 and reasons[-1]["code"] == "diagnostic_budget_exceeded"
    assert path.read_bytes() == before
    assert not (reproduction_root / ".tool-cache/inputs").exists()
