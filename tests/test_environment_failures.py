# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise unavailable real dependencies and process-local kernel refusals."""

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from time import monotonic, sleep
from typing import cast

import pytest

from tests.conftest import SOURCE, payload, snapshots, source_python
from tests.producer_environments import producer_environment
from tests.test_atomic_publication import actual_strace as actual_strace


@contextmanager
def genuine_graph_lock(directory: Path) -> Iterator[None]:
    """Serialise real cached-producer changes and qualification between workers."""
    lock = directory / "actual-producer-fixture.lock"
    assert not lock.is_symlink()
    with lock.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


@pytest.fixture(scope="module")
def missing_tool_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build an actual isolated interpreter with only the verified trace producer."""
    directory = tmp_path_factory.mktemp("missing-tool-environment")
    python = directory / "bin/python"
    wheel = next((SOURCE / ".tool-cache/wheelhouse").glob("coverage-7.16.2-*.whl"))
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == (
        "4358b9c8c0125b460407f3017c6cce8156e904b32772c5630d27112f52bdbfe5"
    )
    python = producer_environment(directory, [wheel])
    return python


@pytest.mark.parametrize(
    "gate",
    [
        "repository_metadata",
        "source_provenance",
        "workflow_policy",
        "dependency_alignment",
        "documentation",
        "repository_inventory",
        "preflight",
    ],
)
def test_actual_required_tool_absence(root: Path, missing_tool_python: Path, gate: str) -> None:
    """Every public guard emits native3 when actual required imports are absent."""
    filename = "preflight.py" if gate == "preflight" else "check_" + gate + ".py"
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools" / filename),
            "--root",
            str(root),
            "--json",
            executable=str(missing_tool_python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
        check=False,
    )
    record = payload(result, 3)
    assert record["reasons"] == [
        {
            "code": "tool_unavailable",
            "detail": "Required local infrastructure condition failed: tool_unavailable.",
            "location": None,
        }
    ]
    if gate == "preflight":
        checks = record["checks"]
        assert isinstance(checks, list) and len(checks) == 18
        assert all(isinstance(check, dict) and check["status"] == "not_run" for check in checks)


def test_actual_subreaper_kernel_denial(root: Path) -> None:
    """An owned child denies its own prctl syscall and preserves17 unavailable roles."""
    program = """import ctypes,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.orchestration import Role,run_plan
from local_scaffold.policy import ROLES
from local_scaffold.reports import Report
class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,157),Filter(0x06,0,0,0x50001),Filter(0x06,0,0,0x7fff0000))
program=Program(4,filters)
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0
assert libc.prctl(22,2,ctypes.byref(program),0,0)==0
report=Report('preflight')
roles=tuple(Role(n,(sys.executable,'-c','pass')) for n in ROLES)
run_plan(Path(sys.argv[2]),report,roles)
sys.exit(report.emit(True))
"""
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools"), str(root)),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
        check=False,
    )
    record = payload(result, 3)
    checks = record["checks"]
    assert isinstance(checks, list) and len(checks) == 18
    assert all(
        isinstance(check, dict)
        and check["status"] == "unavailable"
        and check["reason_codes"] == ["tool_unavailable"]
        for check in checks
    )


def test_actual_missing_tool_with_network_denied(root: Path, missing_tool_python: Path) -> None:
    """A real missing-producer child denies its own sockets and performs no fallback."""
    program = """import ctypes,runpy,socket,sys
class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,41),Filter(0x06,0,0,0x50001),Filter(0x06,0,0,0x7fff0000))
filter_program=Program(4,filters)
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0
assert libc.prctl(22,2,ctypes.byref(filter_program),0,0)==0
try:
    socket.socket(socket.AF_INET,socket.SOCK_STREAM)
except PermissionError:
    pass
else:
    raise RuntimeError('Actual process-local socket denial was not established.')
sys.path.insert(0,sys.argv[1])
script=sys.argv[2]
sys.argv=[script,*sys.argv[3:]]
runpy.run_path(script,run_name='__main__')
"""
    result = subprocess.run(
        source_python(
            "-c",
            program,
            str(SOURCE / "tools"),
            str(SOURCE / "tools/check_dependency_alignment.py"),
            "--root",
            str(root),
            "--json",
            executable=str(missing_tool_python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )
    record = payload(result, 3)
    assert record["reasons"] == [
        {
            "code": "tool_unavailable",
            "detail": "Required local infrastructure condition failed: tool_unavailable.",
            "location": None,
        }
    ]


@pytest.fixture(scope="module")
def genuine_graph_python() -> Path:
    """Reuse a qualified complete owned clone, checking every genuine METADATA anew."""
    provenance_bytes = (SOURCE / "dependency-provenance.json").read_bytes()
    fingerprint = hashlib.sha256(provenance_bytes).hexdigest()
    base = SOURCE / ".tool-cache/native-fixtures/genuine-full-producer-environment"
    assert not any(path.is_symlink() for path in (base, *base.parents[:-1]))
    base.mkdir(parents=True, exist_ok=True)
    recipe = hashlib.sha256(
        (SOURCE / "Makefile").read_bytes() + (SOURCE / ".make/environment.mk").read_bytes()
    ).hexdigest()
    directory = base / (fingerprint + "-" + recipe[:16] + "-uv-hardlink")
    with genuine_graph_lock(base):
        marker = directory / "actual-complete-producer-fixture.json"
        if directory.exists():
            assert marker.is_file() and not marker.is_symlink(), (
                "Incomplete original cache retained."
            )
            assert json.loads(marker.read_text()) == {
                "source_graph_sha256": fingerprint,
                "producer_count": 106,
                "native_clone": "complete-uv-hardlink-graph",
            }
        else:
            subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "environment",
                    "BASE_PYTHON=" + sys.executable,
                    "ENVIRONMENT_DIR=" + str(directory),
                    "ENVIRONMENT_INPUTS=" + str(SOURCE / ".tool-cache/environment-inputs"),
                    "UV_CACHE_DIR=" + str(SOURCE / ".tool-cache/uv-cache"),
                    "ENVIRONMENT_OWNER_SOURCE=" + os.environ["SPIKE_LOG_TEST_OWNER_SOURCE"],
                ],
                cwd=SOURCE,
                capture_output=True,
                timeout=180,
                check=True,
            )
            metadata = next(
                directory.glob("lib/python3.13/site-packages/packaging-*.dist-info/METADATA")
            )
            retained = directory / "original-packaging-METADATA"
            metadata.rename(retained)
            metadata.write_bytes(retained.read_bytes())
            qualify_complete_graph(directory / "bin/python")
            with marker.open("x") as stream:
                json.dump(
                    {
                        "source_graph_sha256": fingerprint,
                        "producer_count": 106,
                        "native_clone": "complete-uv-hardlink-graph",
                    },
                    stream,
                )
        python = directory / "bin/python"
        assert (
            hashlib.sha256(python.read_bytes()).digest()
            == hashlib.sha256(Path(sys.executable).read_bytes()).digest()
        )
        qualify_complete_graph(python)
        return python


def qualify_complete_graph(python: Path) -> None:
    """Read the full actual 106-producer graph and exact original METADATA bytes."""
    check = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import email.parser,hashlib,importlib.metadata,json;observed=[]\nfor d in importlib.metadata.distributions():\n raw=d.read_text('METADATA');assert raw is not None\n headers=email.parser.HeaderParser().parsestr(raw.partition('\\n\\n')[0],headersonly=True)\n observed.append({'name':headers['Name'],'version':headers['Version'],'metadata_sha256':hashlib.sha256(raw.encode()).hexdigest()})\nprint(json.dumps(observed,sort_keys=True))",
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    from packaging.utils import canonicalize_name

    observed = json.loads(check.stdout)
    actual = {canonicalize_name(x["name"]): x["version"] for x in observed}
    expected = {
        canonicalize_name(x["name"]): x["version"]
        for x in json.loads((SOURCE / "dependency-provenance.json").read_text())["packages"]
    }
    assert actual == expected and len(actual) == len(observed) == 106
    expected_metadata = {
        canonicalize_name(x["name"]): x["metadata_sha256"]
        for x in json.loads((SOURCE / "dependency-provenance.json").read_text())["packages"]
    }
    assert {
        canonicalize_name(x["name"]): x["metadata_sha256"] for x in observed
    } == expected_metadata


@pytest.mark.parametrize(
    "case",
    [
        "missing-transitive",
        "missing-direct",
        "wrong-producer",
        "missing-metadata",
        "duplicate-producer",
        "empty-name",
        "empty-version",
    ],
)
def test_actual_complete_producer_graph_refusals(
    root: Path, genuine_graph_python: Path, case: str
) -> None:
    """Actual registered producer changes refuse through the real dependency CLI."""
    prefix = genuine_graph_python.parents[1]
    with genuine_graph_lock(prefix.parent):
        qualify_complete_graph(genuine_graph_python)
        site = prefix / "lib/python3.13/site-packages"
        package = site / "execnet"
        distribution = site / "execnet-2.1.2.dist-info"
        packaging = next(site.glob("packaging-*.dist-info"))
        metadata = packaging / "METADATA"
        original = metadata.read_bytes()
        held = prefix / "held-original-producer"
        expected = 2
        reason = "dependency_alignment.wrong-producer"
        try:
            if case == "missing-transitive":
                held.mkdir()
                package.rename(held / package.name)
                distribution.rename(held / distribution.name)
                reason = "dependency_alignment.missing-transitive"
            elif case == "missing-direct":
                held.mkdir()
                packaging.rename(held / packaging.name)
                expected = 3
                reason = "dependency_alignment.missing-tool"
            elif case == "wrong-producer":
                metadata.write_bytes(original + b"\nX-Actual-Producer-Drift: unqualified\n")
            elif case == "missing-metadata":
                metadata.rename(packaging / "METADATA.actual-original")
            elif case == "empty-name":
                altered = original.replace(b"Name: packaging\n", b"Name:\n", 1)
                assert altered != original
                metadata.write_bytes(altered)
            elif case == "empty-version":
                altered = original.replace(b"Version: 26.3\n", b"Version:\n", 1)
                assert altered != original
                metadata.write_bytes(altered)
            else:
                shutil.copytree(packaging, site / "packaging-duplicate.dist-info")
            result = subprocess.run(
                source_python(
                    str(SOURCE / "tools/check_dependency_alignment.py"),
                    "--root",
                    str(root),
                    "--json",
                    executable=str(genuine_graph_python),
                ),
                cwd=SOURCE,
                capture_output=True,
                timeout=120,
            )
            record = payload(result, expected)
            reasons = record["reasons"]
            assert isinstance(reasons, list)
            assert any(isinstance(item, dict) and item["code"] == reason for item in reasons)
            assert all(
                not isinstance(item, dict) or item["code"] != "unexpected_fault" for item in reasons
            )
        finally:
            if case == "missing-transitive":
                if (held / package.name).exists():
                    (held / package.name).rename(package)
                if (held / distribution.name).exists():
                    (held / distribution.name).rename(distribution)
                held.rmdir()
            elif case == "missing-direct":
                (held / packaging.name).rename(packaging)
                held.rmdir()
            elif case == "missing-metadata":
                (packaging / "METADATA.actual-original").rename(metadata)
            elif case == "duplicate-producer":
                shutil.rmtree(site / "packaging-duplicate.dist-info")
            else:
                metadata.write_bytes(original)
        assert metadata.read_bytes() == original
        qualify_complete_graph(genuine_graph_python)


def test_actual_producer_metadata_disappears_after_graph_read(
    root: Path, genuine_graph_python: Path, actual_strace: Path, tmp_path: Path
) -> None:
    """Remove real METADATA after its first read, refusing the later native reopen."""
    prefix = genuine_graph_python.parents[1]
    with genuine_graph_lock(prefix.parent):
        qualify_complete_graph(genuine_graph_python)
        metadata = prefix / "lib/python3.13/site-packages/zizmor-1.30.1.dist-info/METADATA"
        original = metadata.read_bytes()
        held = metadata.with_name("METADATA.actual-retained")
        assert not held.exists()
        trace = tmp_path / "actual-metadata-reopen.native-trace"
        process = subprocess.Popen(
            [
                str(actual_strace),
                "-f",
                "--kill-on-exit",
                "-yy",
                "-s",
                "4096",
                "-o",
                str(trace),
                "-P",
                str(metadata),
                "-e",
                "trace=openat,close",
                "-e",
                "inject=openat:delay_enter=2s:when=2",
                *source_python(
                    str(SOURCE / "tools/check_dependency_alignment.py"),
                    "--root",
                    str(root),
                    "--json",
                    executable=str(genuine_graph_python),
                ),
            ],
            cwd=SOURCE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = monotonic() + 10
            while monotonic() < deadline:
                lines = trace.read_text().splitlines() if trace.exists() else []
                if any("close(" in line and str(metadata) in line for line in lines):
                    break
                assert process.poll() is None, lines
                sleep(0.001)
            else:
                raise AssertionError("Actual producer METADATA first native read was not observed.")
            metadata.rename(held)
            stdout, stderr = process.communicate(timeout=30)
            record = payload(
                subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 2
            )
            reasons = record["reasons"]
            assert isinstance(reasons, list)
            assert any(
                isinstance(reason, dict) and reason["code"] == "dependency_alignment.wrong-producer"
                for reason in reasons
            )
            assert all(
                not isinstance(reason, dict) or reason["code"] != "unexpected_fault"
                for reason in reasons
            )
            lines = trace.read_text().splitlines()
            opens = [line for line in lines if "openat(" in line and str(metadata) in line]
            assert len(opens) == 2, lines
            assert "O_RDONLY" in opens[0] and "ENOENT" not in opens[0]
            assert "ENOENT" in opens[1] and "DELAYED" in opens[1], opens
            assert held.read_bytes() == original and not metadata.exists()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if held.exists():
                held.rename(metadata)
        assert metadata.read_bytes() == original
        qualify_complete_graph(genuine_graph_python)


@pytest.fixture(
    scope="module",
    params=[
        (
            "3.13.15",
            "20260929",
            "c552deaf9ed0e678dee4ccc760d6dcd7cab33f1bd43e8037123b4a4db8508e14",
            "bb4d05c1f88e8568985e8704afe1822e82700a54bad9317c05c8eb96d3186701",
        ),
        (
            "3.14.7",
            "20260901",
            "3959f92825141e04adf44982d3a83ee57af0877e893b0796e04c1468749d9b04",
            "241bf774a81580bb760adf960b48df7e6b23b1de026c9c912d4ca6be1a08241e",
        ),
    ],
    ids=["unsupported-patch", "unsupported-major"],
)
def actual_unsupported_python(request: pytest.FixtureRequest) -> Path:
    """Qualify each genuine unsupported CPython and its two real fixture producers."""
    version, build, archive_digest, python_digest = cast(tuple[str, str, str, str], request.param)
    base = SOURCE / (".tool-cache/native-fixtures/cpython-" + version)
    python = base / "guard-environment-uv/bin/python"
    if not python.is_file():
        pytest.exit(
            "Required genuine unsupported-interpreter fixture is unavailable.", returncode=3
        )
    assert not any(path.is_symlink() for path in python.parents[:-1])
    assert (
        python.resolve()
        == (base / ("extracted/python/bin/python" + version.rsplit(".", 1)[0])).resolve()
    )
    archive = base / (
        "cpython-"
        + version
        + "+"
        + build
        + "-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
    )
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == archive_digest
    assert hashlib.sha256(python.read_bytes()).hexdigest() == python_digest
    observed = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import hashlib,importlib.metadata,json,platform;print(json.dumps({'version':platform.python_version(),'producers':[{'name':d.metadata['Name'],'version':d.version,'metadata_sha256':hashlib.sha256(d.read_text('METADATA').encode()).hexdigest()} for d in importlib.metadata.distributions()]}))",
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    value = json.loads(observed.stdout)
    assert value["version"] == version
    producers = value["producers"]
    assert len(producers) == 2 and {p["name"] for p in producers} == {"coverage", "packaging"}
    expected = {
        p["name"]: (p["version"], p["metadata_sha256"])
        for p in json.loads((SOURCE / "dependency-provenance.json").read_text())["packages"]
        if p["name"] in ("coverage", "packaging")
    }
    assert {p["name"]: (p["version"], p["metadata_sha256"]) for p in producers} == expected
    return python


def test_actual_unsupported_interpreter(root: Path, actual_unsupported_python: Path) -> None:
    """Actual unsupported versions refuse before incomplete producer-graph handling."""
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/check_dependency_alignment.py"),
            "--root",
            str(root),
            "--json",
            executable=str(actual_unsupported_python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )
    record = payload(result, 2)
    assert record["reasons"] == [
        {
            "code": "dependency_alignment.incompatible-patch",
            "detail": "Required local infrastructure condition failed: "
            "dependency_alignment.incompatible-patch.",
            "location": "dependency-provenance.json",
        }
    ]


def test_actual_unsupported_metadata_interpreter(
    root: Path, actual_unsupported_python: Path
) -> None:
    """The public metadata boundary rejects genuine unsupported interpreter versions."""
    before = snapshots(root)
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/check_repository_metadata.py"),
            "--root",
            str(root),
            "--json",
            executable=str(actual_unsupported_python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )
    record = payload(result, 2)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "repository_metadata.bad-version"
        for reason in reasons
    )
    assert all(
        not isinstance(reason, dict) or reason["code"] != "unexpected_fault" for reason in reasons
    )
    assert snapshots(root) == before


def test_actual_native_tool_short_read_refuses_identity(
    tmp_path: Path, actual_strace: Path
) -> None:
    """A real early EOF from the pinned producer file cannot pass its byte identity."""
    producer = SOURCE / ".tool-cache/native/actionlint/actionlint"
    original = producer.read_bytes()
    original_digest = hashlib.sha256(original).hexdigest()
    program = """import json,sys
sys.path.insert(0,sys.argv[1])
from local_scaffold.dependencies import native_tool
from local_scaffold.reports import Fault
try:
    native_tool('actionlint')
    print(json.dumps({'source_identity_verified':True}))
except Fault as fault:
    print(json.dumps({'code':fault.code,'exit_code':fault.exit_code}))
    sys.exit(fault.exit_code)
"""
    command = source_python("-I", "-c", program, str(SOURCE / "tools"))
    probe = tmp_path / "actual_native_tool_original_reads.native-trace"
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(probe),
            "-e",
            "trace=read",
            *command,
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0 and not result.stderr
    assert json.loads(result.stdout) == {"source_identity_verified": True}
    reads = [line for line in probe.read_bytes().splitlines() if line.startswith(b"read(")]
    ordinal = next(
        index for index, line in enumerate(reads, start=1) if os.fsencode(producer) in line
    )
    trace = tmp_path / "actual_native_tool_early_EOF.native-trace"
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=read",
            "-e",
            "inject=read:retval=0:when=" + str(ordinal),
            *command,
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2 and not result.stderr, (result.stdout, result.stderr)
    assert json.loads(result.stdout) == {"code": "source_identity_mismatch", "exit_code": 2}
    injected = [line for line in trace.read_bytes().splitlines() if b"INJECTED" in line]
    assert len(injected) == 1 and os.fsencode(producer) in injected[0]
    assert b"= 0 (INJECTED)" in injected[0]
    assert hashlib.sha256(producer.read_bytes()).hexdigest() == original_digest
    assert producer.read_bytes() == original


def test_public_cli_actual_unhandled_stat_fault_is_safe(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """A real EIO while inspecting an owned entry reaches safe public fault recovery."""
    target = root / "received-kernel.txt"
    header = "\n".join(
        (SOURCE / "tools/check_repository_inventory.py").read_text().splitlines()[:7]
    )
    target.write_text(header + "\n\nReceived finite input for syscall qualification.\n")
    before = snapshots(root)
    command = source_python(
        str(SOURCE / "tools/check_repository_inventory.py"), "--root", str(root), "--json"
    )
    probe = tmp_path / "actual_original_public_owned_entry.native-trace"
    result = subprocess.run(
        [str(actual_strace), "-qq", "-s", "4096", "-o", str(probe), "-e", "trace=lstat", *command],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    payload(result, 0)
    calls = [line for line in probe.read_bytes().splitlines() if line.startswith(b"lstat(")]
    ordinal = next(
        index for index, line in enumerate(calls, start=1) if os.fsencode(target) in line
    )
    trace = tmp_path / "actual_public_owned_entry_EIO.native-trace"
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=lstat",
            "-e",
            "inject=lstat:error=EIO:when=" + str(ordinal),
            *command,
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    value = payload(result, 2)
    assert value["reasons"] == [
        {
            "code": "unexpected_fault",
            "location": None,
            "detail": "Required local infrastructure condition failed: unexpected_fault.",
        }
    ]
    injected = [line for line in trace.read_bytes().splitlines() if b"INJECTED" in line]
    assert len(injected) == 1 and os.fsencode(target) in injected[0]
    assert b"EIO" in injected[0]
    assert os.fsencode(root) not in result.stdout
    assert snapshots(root) == before
