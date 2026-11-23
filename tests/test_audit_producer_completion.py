# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Retain real audit output across native interruption and concurrent source drift."""

import ast
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest

from local_scaffold.limits import MAX_CAPTURE
from tests.conftest import payload, source_python
from tests.test_atomic_publication import actual_strace as actual_strace


def audit_process(trace: bytes) -> int | None:
    """Find the actual successful exec of this traced native audit.

    Parameters
    ----------
    trace : bytes
        Original owned strace output for the public guard and its descendants.

    Returns
    -------
    int or None
        Observed audit child PID, or None before its successful exec.
    """
    matches = [
        line
        for line in trace.splitlines()
        if b"execve(" in line and b'"pip_audit", "--strict"' in line and b"= 0" in line
    ]
    return int(matches[-1].split()[0]) if matches else None


def completed_audit_output(trace: bytes, process: int) -> bytes | None:
    """Require complete JSON actually written by the selected native child.

    Parameters
    ----------
    trace : bytes
        Complete currently observed syscall output, including native write results.
    process : int
        Audit PID selected from its successful exec in the same trace.

    Returns
    -------
    bytes or None
        Complete original JSON for all 104 components, or None before it was emitted.
    """
    pattern = re.compile(
        rb"^" + str(process).encode() + rb'\s+write\(1, ("(?:[^"\\]|\\.)*"), (\d+)\)\s+=\s+(\d+)',
        re.MULTILINE,
    )
    chunks: list[bytes] = []
    for match in pattern.finditer(trace):
        data: object = ast.literal_eval("b" + match[1].decode("ascii"))
        assert isinstance(data, bytes)
        assert len(data) == int(match[2]) == int(match[3])
        chunks.append(data)
    original = b"".join(chunks)
    try:
        value = json.loads(original)
    except json.JSONDecodeError:
        return None
    assert set(value) == {"dependencies", "fixes"}
    assert len(value["dependencies"]) == 104
    return original


@pytest.mark.parametrize("mode", ["complete-output-interruption", "concurrent-source-drift"])
def test_real_audit_completion_never_admits_a_failed_attempt(
    audited_clone: Path, tmp_path: Path, actual_strace: Path, mode: str
) -> None:
    """Preserve full native JSON and prior admission without accepting either failure."""
    store = audited_clone / ".tool-cache/security-admissions"
    prior_head = (store / "HEAD.json").read_bytes()
    prior_objects = {path.name: path.read_bytes() for path in (store / "objects").iterdir()}
    audit = audited_clone / ".tool-cache/security/pip-audit.json"
    prior_audit = audit.read_bytes()
    trace = tmp_path / "producer-completion.trace"
    trace.touch(exist_ok=False)
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
        *source_python(
            str(audited_clone / "tools/check_dependency_alignment.py"),
            "--root",
            str(audited_clone),
            "--produce-audit",
            "--json",
        ),
    ]
    acted = False
    process = None
    started = time.monotonic()
    with subprocess.Popen(
        command,
        cwd=audited_clone,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    ) as child:
        try:
            while child.poll() is None:
                assert time.monotonic() - started < 90
                original_trace = trace.read_bytes()
                if process is None:
                    process = audit_process(original_trace)
                if process is not None and not acted:
                    if mode == "concurrent-source-drift":
                        with (audited_clone / "tools/local_scaffold/policy.py").open(
                            "ab"
                        ) as stream:
                            stream.write(b"\n")
                            stream.flush()
                            os.fsync(stream.fileno())
                        acted = True
                    elif completed_audit_output(original_trace, process):
                        os.kill(process, signal.SIGTERM)
                        acted = True
                time.sleep(0.01)
            stdout, stderr = child.communicate(timeout=5)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
    assert acted and process is not None
    result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
    report = payload(result, 2)
    assert report["scope"] == "audit_produce"
    expected = (
        "tool_failed" if mode == "complete-output-interruption" else "source_identity_mismatch"
    )
    assert expected in str(report["reasons"]) and "unexpected_fault" not in str(report["reasons"])
    assert audit.read_bytes() == prior_audit
    assert (store / "HEAD.json").read_bytes() != prior_head
    for name, original in prior_objects.items():
        assert (store / "objects" / name).read_bytes() == original
    head = json.loads((store / "HEAD.json").read_bytes())
    assert head["state"] == "terminal"
    receipt_bytes = (store / "objects" / (head["receipt_sha256"] + ".json")).read_bytes()
    assert hashlib.sha256(receipt_bytes).hexdigest() == head["receipt_sha256"]
    receipt = json.loads(receipt_bytes)
    assert receipt["generation"] == head["generation"]
    assert receipt["outcome"] == "refused" and receipt["component_count"] == 104
    assert receipt["native_exit"] == (-15 if mode == "complete-output-interruption" else 0)
    assert receipt["produced_at"] is not None
    assert receipt["audit_sha256"] == receipt["stdout_sha256"]
    original_output = (store / "objects" / (receipt["stdout_sha256"] + ".json")).read_bytes()
    assert hashlib.sha256(original_output).hexdigest() == receipt["stdout_sha256"]
    assert len(json.loads(original_output)["dependencies"]) == 104


def native_audit_identity(process: int, root: Path) -> str:
    """Bind a traced auditor to its real command, parent and process lifetime.

    Parameters
    ----------
    process : int
        Auditor PID obtained from its successful exec in the owned native trace.
    root : Path
        Isolated installation whose public guard must be the direct parent.

    Returns
    -------
    str
        Original kernel process-start counter used to reject PID reuse.
    """
    directory = Path("/proc") / str(process)
    fields = (directory / "stat").read_text().rsplit(") ", 1)[1].split()
    arguments = (directory / "cmdline").read_bytes().split(b"\0")
    assert arguments[1:5] == [b"-I", b"-B", b"-m", b"pip_audit"]
    parent = Path("/proc") / fields[1] / "cmdline"
    assert os.fsencode(root / "tools/check_dependency_alignment.py") in parent.read_bytes()
    return fields[19]


def signal_native_audit(process: int, identity: str, signum: signal.Signals) -> None:
    """Signal only the original owned auditor, refusing a reused PID.

    Parameters
    ----------
    process : int
        Previously observed native auditor PID.
    identity : str
        Kernel process-start counter captured with its original command.
    signum : signal.Signals
        Actual native stop, continue or termination signal for this control.
    """
    fields = (Path("/proc") / str(process) / "stat").read_text().rsplit(") ", 1)[1].split()
    assert fields[19] == identity
    os.kill(process, signum)


@pytest.mark.parametrize("mode", ["interrupted-corrupt-pipe", "missing-context-corrupt-pipe"])
def test_real_corrupted_audit_pipe_preserves_diagnostic_exhaustion(
    audited_clone: Path, tmp_path: Path, actual_strace: Path, mode: str
) -> None:
    """Separate genuine native output from an adverse pipe and retain terminal failure."""
    store = audited_clone / ".tool-cache/security-admissions"
    prior_head = (store / "HEAD.json").read_bytes()
    prior_objects = {path.name: path.read_bytes() for path in (store / "objects").iterdir()}
    audit = audited_clone / ".tool-cache/security/pip-audit.json"
    prior_audit = audit.read_bytes()
    component = json.loads(prior_audit)["dependencies"][0]
    assert set(component) == {"name", "version", "vulns"}
    prefix = (
        b'{"dependencies":['
        + b",".join([json.dumps(component, separators=(",", ":")).encode()] * 300)
        + b","
    )
    suffix = b'],"fixes":[]}\n'
    (tmp_path / "external-adverse-prefix.bin").write_bytes(prefix)
    (tmp_path / "external-adverse-suffix.bin").write_bytes(suffix)
    trace = tmp_path / "actual-corrupted-audit-pipe.native-trace"
    trace.touch(exist_ok=False)
    output = tmp_path / "actual-public-report.json"
    errors = tmp_path / "actual-public-stderr.bin"
    configuration = audited_clone / "dependency-provenance.json"
    original_configuration = configuration.read_bytes()
    held = tmp_path / "actual-held-original-provenance.json"
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
        *source_python(
            str(audited_clone / "tools/check_dependency_alignment.py"),
            "--root",
            str(audited_clone),
            "--produce-audit",
            "--json",
        ),
    ]
    process = None
    identity = None
    writer = None
    original = None
    acted = False
    started = time.monotonic()
    with (
        output.open("wb") as stdout,
        errors.open("wb") as stderr,
        subprocess.Popen(
            command,
            cwd=audited_clone,
            stdout=stdout,
            stderr=stderr,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        ) as child,
    ):
        try:
            while child.poll() is None:
                assert time.monotonic() - started < 90
                raw = trace.read_bytes()
                if process is None:
                    process = audit_process(raw)
                    if process is not None:
                        identity = native_audit_identity(process, audited_clone)
                        signal_native_audit(process, identity, signal.SIGSTOP)
                        assert completed_audit_output(raw, process) is None
                        writer = os.open(
                            Path("/proc") / str(process) / "fd/1", os.O_WRONLY | os.O_CLOEXEC
                        )
                        assert stat.S_ISFIFO(os.fstat(writer).st_mode)
                        assert os.write(writer, prefix) == len(prefix)
                        signal_native_audit(process, identity, signal.SIGCONT)
                if process is not None and not acted:
                    original = completed_audit_output(raw, process)
                    if original is not None:
                        assert writer is not None and identity is not None
                        assert os.write(writer, suffix) == len(suffix)
                        os.close(writer)
                        writer = None
                        (tmp_path / "authentic-native-auditor104.json").write_bytes(original)
                        if mode == "interrupted-corrupt-pipe":
                            signal_native_audit(process, identity, signal.SIGTERM)
                        else:
                            configuration.rename(held)
                        acted = True
                time.sleep(0.01)
            child.wait(timeout=5)
        finally:
            if writer is not None:
                os.close(writer)
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            if held.exists():
                held.rename(configuration)
    assert acted and original is not None and process is not None
    expected = 2 if mode == "interrupted-corrupt-pipe" else 3
    result = subprocess.CompletedProcess(
        command, child.returncode, output.read_bytes(), errors.read_bytes()
    )
    report = payload(result, expected)
    reasons = report["reasons"]
    assert isinstance(reasons, list) and len(reasons) == 256
    assert isinstance(reasons[-1], dict) and reasons[-1]["code"] == "diagnostic_budget_exceeded"
    assert configuration.read_bytes() == original_configuration and not held.exists()
    assert audit.read_bytes() == prior_audit and (store / "HEAD.json").read_bytes() != prior_head
    for name, data in prior_objects.items():
        assert (store / "objects" / name).read_bytes() == data
    head = json.loads((store / "HEAD.json").read_bytes())
    assert head["state"] == "terminal"
    receipt_bytes = (store / "objects" / (head["receipt_sha256"] + ".json")).read_bytes()
    assert hashlib.sha256(receipt_bytes).hexdigest() == head["receipt_sha256"]
    receipt = json.loads(receipt_bytes)
    assert receipt["outcome"] == ("refused" if expected == 2 else "unavailable")
    assert receipt["native_exit"] == (-15 if expected == 2 else 0)
    assert receipt["component_count"] == 301 and receipt["produced_at"] is not None
    assert receipt["audit_sha256"] == receipt["stdout_sha256"]
    delivered = (store / "objects" / (receipt["stdout_sha256"] + ".json")).read_bytes()
    assert hashlib.sha256(delivered).hexdigest() == receipt["stdout_sha256"]
    assert delivered == prefix + original + suffix
    assert len(json.loads(delivered)["dependencies"]) == 301
    assert len(json.loads(original)["dependencies"]) == 104
    assert not (Path("/proc") / str(process)).exists()
