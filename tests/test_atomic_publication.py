# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise real public inventory publication with pinned native syscall faults."""

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python

GOLDEN = (
    b'{"capabilities": [], "claims": [], "evidence_maturity": "architecture_only", '
    b'"lifecycle": "public_repository", "qualified_owned_schema_ids": [], '
    b'"repository_name": "SPIKE-LOG", "source_metadata": '
    b'{"path": "repository-domain.json", "sha256": '
    b'"bac894998964a4c34eb2be459b471a5ccda9ba18c6333f76d1875bc403e12a5c"}}\n'
)


@pytest.fixture(scope="module")
def actual_strace() -> Path:
    """Require the genuine pinned Ubuntu fixture; absence never simulates success."""
    base = SOURCE / ".tool-cache/native-fixtures/strace-6.8-0ubuntu2"
    executable = base / "extracted/usr/bin/strace"
    if not executable.is_file():
        pytest.exit("Required native strace fixture is unavailable.", returncode=3)
    assert not any(path.is_symlink() for path in (executable, *executable.parents[:-1]))
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == (
        "28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001"
    )
    copyright_file = base / "extracted/usr/share/doc/strace/copyright"
    assert hashlib.sha256(copyright_file.read_bytes()).hexdigest() == (
        "40e4ca01654c733c06fabee65168da4c177117b1bd084f3a752bc8a989736e04"
    )
    version = subprocess.run(
        [str(executable), "--version"], capture_output=True, timeout=10, check=True
    )
    assert b"strace -- version 6.8" in version.stdout
    return executable


@pytest.mark.parametrize(
    ("name", "faults", "native_exit", "visible"),
    [
        ("file-fsync", ("fsync:error=EIO:when=1",), 2, False),
        ("directory-fsync", ("fsync:error=EIO:when=2",), 2, True),
        (
            "exclusive-link",
            ("link:error=EPERM:when=1", "linkat:error=EPERM:when=1"),
            2,
            False,
        ),
        (
            "temporary-unlink",
            ("unlink:error=EIO:when=1", "unlinkat:error=EIO:when=1"),
            2,
            True,
        ),
        ("interrupt-before-link", ("fsync:signal=SIGTERM:when=1",), 3, False),
        ("interrupt-after-link", ("fsync:signal=SIGTERM:when=2",), 3, True),
        ("sigint-before-link", ("fsync:signal=SIGINT:when=1",), 3, False),
        ("sigint-after-link", ("fsync:signal=SIGINT:when=2",), 3, True),
        (
            "interrupted-link",
            (
                "link:error=EINTR:signal=SIGTERM:when=1",
                "linkat:error=EINTR:signal=SIGTERM:when=1",
            ),
            3,
            False,
        ),
    ],
)
def test_actual_atomic_syscall_faults(
    root: Path,
    tmp_path: Path,
    actual_strace: Path,
    name: str,
    faults: tuple[str, ...],
    native_exit: int,
    visible: bool,
) -> None:
    """Actual fsync/link/unlink/signals preserve complete publication and recovery."""
    assert hashlib.sha256((root / "repository-domain.json").read_bytes()).hexdigest() == (
        "bac894998964a4c34eb2be459b471a5ccda9ba18c6333f76d1875bc403e12a5c"
    )
    unrelated = root / "unrelated-existing-file.txt"
    unrelated.write_bytes(b"Independent original sentinel; never replace or clean up.\n")
    original = snapshots(root)
    trace = tmp_path / (name + ".actual-native-trace")
    command = [
        str(actual_strace),
        "-f",
        "--kill-on-exit",
        "-o",
        str(trace),
        "-e",
        "trace=fsync,link,linkat,unlink,unlinkat",
    ]
    if native_exit == 2:
        command.append("--seccomp-bpf")
    for fault in faults:
        command.extend(("-e", "inject=" + fault))
    command.extend(
        source_python(
            str(SOURCE / "tools/check_repository_inventory.py"),
            "--root",
            str(root),
            "--mode",
            "generate",
            "--output",
            "atomic-output.json",
            "--json",
        )
    )
    result = subprocess.run(command, cwd=SOURCE, capture_output=True, timeout=120)
    report = payload(result, native_exit)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert reasons == [
        {
            "code": "interrupted" if native_exit == 3 else "output_failure",
            "detail": "Required local infrastructure condition failed: "
            + ("interrupted." if native_exit == 3 else "output_failure."),
            "location": None if native_exit == 3 else "atomic-output.json",
        }
    ]
    output = root / "atomic-output.json"
    assert output.exists() == visible
    if visible:
        assert output.read_bytes() == GOLDEN
    assert not list(root.glob(".spike-log-inventory-*"))
    after = snapshots(root)
    assert {key: value for key, value in after.items() if key != "atomic-output.json"} == original
    actual_trace = trace.read_bytes()
    if any(":error=" in fault for fault in faults):
        assert b"INJECTED" in actual_trace
    if native_exit == 3:
        assert (b"SIGINT" if name.startswith("sigint-") else b"SIGTERM") in actual_trace
    retry = run_guard(
        "repository_inventory",
        root,
        "--mode",
        "generate",
        "--output",
        "atomic-output.json",
    )
    repeated = payload(retry, 2 if visible else 0)
    if visible:
        repeated_reasons = repeated["reasons"]
        assert isinstance(repeated_reasons, list)
        assert any(
            isinstance(reason, dict) and reason["code"] == "output_exists"
            for reason in repeated_reasons
        )
    assert output.read_bytes() == GOLDEN
    assert not list(root.glob(".spike-log-inventory-*"))
    assert unrelated.read_bytes() == original["unrelated-existing-file.txt"]


def test_publication_actual_file_size_limit(root: Path) -> None:
    """The real public CLI handles kernel RLIMIT_FSIZE without partial publication."""
    original = snapshots(root)
    program = """import resource,runpy,signal,sys
original_limits=resource.getrlimit(resource.RLIMIT_FSIZE)
resource.setrlimit(resource.RLIMIT_FSIZE,(128,original_limits[1]))
signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
sys.path.insert(0,sys.argv[1])
script=sys.argv[2]
sys.argv=[script,*sys.argv[3:]]
try:
    runpy.run_path(script,run_name='__main__')
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE,original_limits)
"""
    result = subprocess.run(
        source_python(
            "-c",
            program,
            str(SOURCE / "tools"),
            str(SOURCE / "tools/check_repository_inventory.py"),
            "--root",
            str(root),
            "--mode",
            "generate",
            "--output",
            "size-limited-output.json",
            "--json",
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )
    record = payload(result, 2)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "output_failure" for reason in reasons
    )
    assert not (root / "size-limited-output.json").exists()
    assert not list(root.glob(".spike-log-inventory-*"))
    assert snapshots(root) == original
    payload(
        run_guard(
            "repository_inventory",
            root,
            "--mode",
            "generate",
            "--output",
            "size-limited-output.json",
        ),
        0,
    )
    assert (root / "size-limited-output.json").read_bytes() == GOLDEN


def test_publication_actual_write_permission(root: Path) -> None:
    """An actual unprivileged child cannot publish in a nonwritable destination."""
    assert os.geteuid() != 0, "The publication fixture requires an unprivileged caller."
    directory = root / "permission-boundary"
    directory.mkdir()
    original = snapshots(root)
    mode = directory.stat().st_mode & 0o777
    directory.chmod(0o555)
    try:
        result = run_guard(
            "repository_inventory",
            root,
            "--mode",
            "generate",
            "--output",
            "permission-boundary/output.json",
        )
        record = payload(result, 2)
        reasons = record["reasons"]
        assert isinstance(reasons, list)
        assert any(
            isinstance(reason, dict) and reason["code"] == "output_failure" for reason in reasons
        )
        assert not list(directory.iterdir())
        assert snapshots(root) == original
    finally:
        directory.chmod(mode)
