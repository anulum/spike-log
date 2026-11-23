# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise the genuine shared Git-operation deadline with native cleanup delays."""

from __future__ import annotations

import ast
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

import pytest

from local_scaffold.limits import MAX_CAPTURE
from tests.conftest import SOURCE, source_python
from tests.test_atomic_publication import actual_strace as actual_strace
from tests.test_provenance_local import MANIFEST, OWNER

_PROGRAM = """
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.committed_source import verify_committed_source
from local_scaffold.reports import Fault
owner=Path(sys.argv[2])
manifest=json.loads(Path(sys.argv[3]).read_bytes())
files={row["path"]:(owner/row["path"]).read_bytes() for row in manifest["files"]}
try:
    verify_committed_source(owner,manifest,files)
except Fault as error:
    print(json.dumps({"code":error.code,"exit_code":error.exit_code}))
    raise SystemExit(error.exit_code)
print(json.dumps({"completed":True}))
"""


@pytest.fixture(scope="module")
def actual_cleanup_calls(
    tmp_path_factory: pytest.TempPathFactory, actual_strace: Path
) -> tuple[int, int]:
    """Observe the real first and last event-loop cleanup calls, without choosing guessed ordinals."""
    directory = tmp_path_factory.mktemp("native-git-deadline-baseline")
    trace = directory / "baseline.trace"
    command = [
        str(actual_strace),
        "-f",
        "-qq",
        "-s",
        "4096",
        "-o",
        str(trace),
        "-e",
        "trace=execve,epoll_ctl,exit_group",
        *source_python("-B", "-c", _PROGRAM, str(SOURCE / "tools"), str(OWNER), str(MANIFEST)),
    ]
    result = subprocess.run(command, cwd=SOURCE, capture_output=True, timeout=30)
    assert result.returncode == 0 and json.loads(result.stdout) == {"completed": True}, (
        result.stdout,
        result.stderr,
    )
    lines = trace.read_bytes().splitlines()
    parent = lines[0].split()[0]
    commands = [
        index
        for index, line in enumerate(lines)
        if b'execve("/usr/bin/git"' in line and b"= 0" in line
    ]
    assert len(commands) == 4
    controls = [
        (index, line)
        for index, line in enumerate(lines)
        if line.split()[0] == parent and b"epoll_ctl(" in line
    ]
    assert controls and b"EPOLL_CTL_DEL" in controls[-1][1]
    first = [
        (ordinal, index, line)
        for ordinal, (index, line) in enumerate(controls, 1)
        if commands[0] < index < commands[1] and b"EPOLL_CTL_DEL" in line
    ]
    assert first and b"EPOLL_CTL_DEL" in first[-1][2]
    return first[-1][0], len(controls)


@pytest.mark.parametrize("phase", ("before-next-git", "after-last-git"))
def test_actual_cleanup_delay_preserves_shared_leaf_deadline(
    tmp_path: Path, actual_strace: Path, actual_cleanup_calls: tuple[int, int], phase: str
) -> None:
    """A real 125-second syscall delay must exhaust the unchanged 120-second source deadline."""
    ordinal = actual_cleanup_calls[phase == "after-last-git"]
    trace = tmp_path / "actual-expired-cleanup.trace"
    command = [
        str(actual_strace),
        "-f",
        "-qq",
        "--kill-on-exit",
        "-s",
        "4096",
        "-o",
        str(trace),
        "-e",
        "trace=execve,epoll_ctl,exit_group",
        "-e",
        "inject=epoll_ctl:delay_enter=125s:when=" + str(ordinal),
        *source_python("-B", "-c", _PROGRAM, str(SOURCE / "tools"), str(OWNER), str(MANIFEST)),
    ]
    started = time.monotonic()
    with subprocess.Popen(
        command, cwd=SOURCE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    ) as child:
        try:
            stdout, stderr = child.communicate(timeout=160)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    assert time.monotonic() - started >= 125
    assert child.returncode == 3 and json.loads(stdout) == {
        "code": "tool_timeout",
        "exit_code": 3,
    }, (stdout, stderr)
    assert b"DELAYED" in trace.read_bytes()


def test_original_native_tree_and_adverse_pipe_are_separate(
    tmp_path: Path, actual_strace: Path
) -> None:
    """Preserve authentic native Git bytes and refuse a separately written adverse pipe record."""
    baseline = subprocess.run(
        [
            "/usr/bin/git",
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(OWNER),
            "ls-tree",
            "-rz",
            "--full-tree",
            "HEAD",
        ],
        capture_output=True,
        timeout=30,
        check=True,
    ).stdout
    (tmp_path / "authentic-native-tree.bin").write_bytes(baseline)
    adverse = b"\0adverse-native-tree-record\0"
    (tmp_path / "adverse-pipe-bytes.bin").write_bytes(adverse)
    trace = tmp_path / "native-tree-pipe.trace"
    command = [
        str(actual_strace),
        "-f",
        "-qq",
        "--kill-on-exit",
        "-s",
        str(MAX_CAPTURE),
        "-o",
        str(trace),
        "-e",
        "trace=execve,write,exit_group",
        "-e",
        "inject=exit_group:delay_enter=2s",
        *source_python("-B", "-c", _PROGRAM, str(SOURCE / "tools"), str(OWNER), str(MANIFEST)),
    ]
    target = None
    wrote = False
    genuine = b""
    started = time.monotonic()
    with subprocess.Popen(
        command, cwd=SOURCE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    ) as child:
        try:
            while child.poll() is None:
                assert time.monotonic() - started < 45
                if trace.exists():
                    original_trace = trace.read_bytes()
                    if target is None:
                        executions = [
                            line
                            for line in original_trace.splitlines()
                            if b'execve("/usr/bin/git"' in line
                            and b'"ls-tree"' in line
                            and b"= 0" in line
                        ]
                        if executions:
                            target = int(executions[-1].split()[0])
                    if target is not None and not wrote:
                        pattern = re.compile(
                            rb"^"
                            + str(target).encode()
                            + rb'\s+write\(1, ("(?:[^"\\]|\\.)*"), (\d+)\)\s+=\s+(\d+)',
                            re.MULTILINE,
                        )
                        chunks = []
                        for match in pattern.finditer(original_trace):
                            data = ast.literal_eval("b" + match[1].decode("ascii"))
                            assert isinstance(data, bytes) and len(data) == int(match[2]) == int(
                                match[3]
                            )
                            chunks.append(data)
                        genuine = b"".join(chunks)
                        if genuine == baseline:
                            process = Path("/proc") / str(target)
                            identity = (process / "stat").read_text().rsplit(") ", 1)[1].split()[19]
                            assert b"ls-tree" in (process / "cmdline").read_bytes()
                            descriptor = os.open(process / "fd/1", os.O_WRONLY)
                            try:
                                assert (process / "stat").read_text().rsplit(") ", 1)[1].split()[
                                    19
                                ] == identity
                                assert os.write(descriptor, adverse) == len(adverse)
                                wrote = True
                            finally:
                                os.close(descriptor)
                time.sleep(0.01)
            stdout, stderr = child.communicate(timeout=5)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    assert target is not None and wrote and genuine == baseline
    assert child.returncode == 2 and json.loads(stdout) == {
        "code": "source_identity_mismatch",
        "exit_code": 2,
    }, (stdout, stderr)
    assert any(
        line.split()[0] == str(target).encode() and b"exit_group(0)" in line
        for line in trace.read_bytes().splitlines()
    )
