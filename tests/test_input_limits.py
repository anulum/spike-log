# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check public parser limits on actual bytes and finite native files."""

import json
import math
import os
import signal
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path

import pytest

from local_scaffold.inputs import (
    decode,
    parse_json,
    read_bytes,
    relative_path,
    root_directory,
    validate_value,
    yaml_object,
)
from local_scaffold.reports import Fault
from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python, stop
from tests.test_atomic_publication import actual_strace as actual_strace


@pytest.mark.parametrize("value", [{1: "not-string"}, object(), math.inf, [0] * 100001])
def test_json_value_refusals(value: object) -> None:
    """Non-JSON types and true count limits refuse under the public parser API."""
    with pytest.raises(Fault):
        validate_value(value)


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":1,"a":2}',
        b"[NaN]",
        b"[Infinity]",
        b'"\\ud800"',
        b'"\\u001b"',
        b"[" * 65 + b"0" + b"]" * 65,
        b" " * 1048577,
    ],
)
def test_raw_parser_refusals(data: bytes) -> None:
    """Native byte parsing refuses malformed scalar/depth/size input before use."""
    with pytest.raises(Fault):
        parse_json(data)


@pytest.mark.parametrize(
    "text",
    [
        "a: &alias [1]\nb: *alias\n",
        "a: 1\na: 2\n",
        "!!python/object:os.system {}\n",
        "a: !custom value\n",
        "[one,two]",
        "a: [",
        "? [one,two]\n: value\n",
        "a: 2026-10-02\n",
        "a: .inf\n",
        "<<: {a: 1}\n",
        "a: " + "[" * 65 + "0" + "]" * 65,
    ],
)
def test_safe_yaml_refusals(root: Path, text: str) -> None:
    """Real YAML events, explicit types and native parser errors remain closed."""
    (root / "config.yml").write_text(text)
    with pytest.raises(Fault):
        yaml_object(root, "config.yml")


def test_actual_regular_file_and_path_limits(root: Path) -> None:
    """A real FIFO never blocks a read and unsafe relative paths never escape."""
    os.mkfifo(root / "named-pipe")
    with pytest.raises(Fault) as pipe:
        read_bytes(root, "named-pipe")
    assert pipe.value.code == "repository_inventory.special-file"
    with pytest.raises(Fault):
        relative_path(root, "../outside")
    with pytest.raises(Fault):
        decode(b"\x7f")
    with pytest.raises(Fault):
        parse_json(b" " * 1048577)
    assert parse_json(b'{"v":[true,false,null,1,1.5,"scalar"]}') == {
        "v": [True, False, None, 1, 1.5, "scalar"]
    }


def test_exact_value_limit_and_workflow_lines(root: Path) -> None:
    """True value counting admits its exact boundary and refuses an extra item."""
    data = b"[" + b",".join([b'"x"'] * 99999) + b"]"
    assert len(data) < 1048576
    parsed = parse_json(data)
    assert isinstance(parsed, list)
    assert len(parsed) == 99999
    path = root / "large.yml"
    path.write_text("# comment\n" * 1001)
    with pytest.raises(Fault):
        yaml_object(root, "large.yml", workflow=True)


def test_actual_post_stat_read_bound() -> None:
    """A genuine zero-size proc regular file must still obey the read byte cap."""
    with pytest.raises(Fault) as error:
        read_bytes(Path("/proc"), str(os.getpid()) + "/status", 1)
    assert error.value.code == "resource_limit"


def test_actual_unavailable_ancestor_and_root_file(root: Path) -> None:
    """Real denied traversal and nondirectory roots retain native availability meaning."""
    regular = root / "regular-file"
    regular.write_text("actual file")
    with pytest.raises(Fault) as file:
        root_directory(str(regular))
    assert file.value.exit_code == 3 and file.value.code == "root_unavailable"
    directory = root / "denied-directory"
    directory.mkdir()
    (directory / "child").write_text("actual unreadable path")
    directory.chmod(0)
    try:
        with pytest.raises(Fault) as traversal:
            relative_path(root, "denied-directory/child")
        assert traversal.value.code == "input_unavailable" and traversal.value.exit_code == 3
    finally:
        directory.chmod(0o700)


def test_actual_symlink_and_missing_repository_roots(root: Path, tmp_path: Path) -> None:
    """The public guard refuses an actual root link and reports a missing root unavailable."""
    before = snapshots(root)
    linked = tmp_path / "linked-root"
    linked.symlink_to(root, target_is_directory=True)
    for candidate, expected_exit, expected_reason in (
        (linked, 2, "root_symlink"),
        (tmp_path / "missing-root", 3, "root_unavailable"),
    ):
        report = payload(run_guard("repository_metadata", candidate), expected_exit)
        reasons = report["reasons"]
        assert isinstance(reasons, list) and len(reasons) == 1
        reason = reasons[0]
        assert isinstance(reason, dict) and reason["code"] == expected_reason
        assert reason["location"] is None
    assert snapshots(root) == before


@pytest.mark.parametrize("parent_name", ["received", "inside"])
@pytest.mark.parametrize("stage", ["checked", "opened"])
def test_actual_received_parent_substitution(
    tmp_path: Path, actual_strace: Path, parent_name: str, stage: str
) -> None:
    """Held directory descriptors refuse or outlive genuine parent-link substitution."""
    received = tmp_path / "received"
    inside = received / "inside"
    inside.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (inside / "received.json").write_bytes(b"original-owned-source\n")
    (outside / "received.json").write_bytes(b"outside-owned-sentinel\n")
    if parent_name == "received":
        (outside / "inside").mkdir()
        (outside / "inside/received.json").write_bytes(b"outside-owned-sentinel\n")
    parent = received if parent_name == "received" else inside
    saved = parent.with_name(parent.name + "-original")
    marker = tmp_path / "reader.pid"
    trace = tmp_path / "parent.native-trace"
    program = """import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.inputs import read_bytes
from local_scaffold.reports import Fault
Path(sys.argv[3]).write_text(str(os.getpid()))
before=len(list(Path('/proc/self/fd').iterdir()))
try:
    data=read_bytes(Path(sys.argv[2]),'inside/received.json')
    result={'body':data.decode('ascii')}
except Fault as fault:
    result={'code':fault.code,'exit_code':fault.exit_code}
result['descriptors_before']=before
result['descriptors_after']=len(list(Path('/proc/self/fd').iterdir()))
print(json.dumps(result),flush=True)
"""
    syscall = "lstat" if stage == "checked" else "openat"
    watched = inside if stage == "checked" else parent.parent
    command = [
        str(actual_strace),
        "-qq",
        "--kill-on-exit",
        "-o",
        str(trace),
        "-e",
        "trace=lstat,openat",
        "-P",
        str(watched),
        "-e",
        "inject=" + syscall + ":signal=SIGSTOP:when=1",
        *source_python(
            "-I", "-B", "-c", program, str(SOURCE / "tools"), str(received), str(marker)
        ),
    ]
    process = subprocess.Popen(
        command,
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            observed = trace.read_text() if trace.exists() else ""
            if marker.exists() and "--- stopped by SIGSTOP ---" in observed:
                pid = int(marker.read_text())
                identity = (
                    (Path("/proc") / str(pid) / "stat").read_text().rsplit(") ", 1)[1].split()
                )
                assert int(identity[1]) == process.pid and identity[0] in {"T", "t"}
                break
            assert process.poll() is None, observed
            assert time.monotonic() < deadline, observed
            time.sleep(0.001)
        with ExitStack() as restore:
            parent.rename(saved)
            restore.callback(saved.rename, parent)
            parent.symlink_to(outside, target_is_directory=True)
            restore.callback(parent.unlink)
            current = (Path("/proc") / str(pid) / "stat").read_text().rsplit(") ", 1)[1].split()
            assert current[19] == identity[19] and int(current[1]) == process.pid
            os.kill(pid, signal.SIGCONT)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == 0 and not stderr, (stdout, stderr)
            result = json.loads(stdout)
            assert result["descriptors_before"] == result["descriptors_after"]
            del result["descriptors_before"], result["descriptors_after"]
            assert result == (
                {"code": "input_unavailable", "exit_code": 3}
                if stage == "checked"
                else {"body": "original-owned-source\n"}
            )
            native = trace.read_text()
            assert "--- stopped by SIGSTOP ---" in native and "SIGCONT" in native
            if stage == "opened":
                assert any(
                    "openat(" in line
                    and ('"' + parent.name + '"') in line
                    and "O_NOFOLLOW" in line
                    and "O_DIRECTORY" in line
                    for line in native.splitlines()
                )
    finally:
        stop(process, group=True, timeout=3)
    assert (inside / "received.json").read_bytes() == b"original-owned-source\n"
    assert (outside / "received.json").read_bytes() == b"outside-owned-sentinel\n"
