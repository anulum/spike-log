# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise real network production, current offline admission and foreign-root refusal."""

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.conftest import SOURCE, clone_dependency, payload, run_guard, snapshots, source_python
from tests.test_atomic_publication import actual_strace as actual_strace


def test_real_fresh_producer_and_offline_admission(root: Path) -> None:
    """Produce through the genuine pinned CLI and consume its actual complete result twice."""
    store = SOURCE / ".tool-cache/security-admissions"
    result = run_guard("dependency_alignment", SOURCE, "--produce-audit")
    record = payload(result, 0)
    assert record["scope"] == "audit_produce"
    head_bytes = (store / "HEAD.json").read_bytes()
    head = json.loads(head_bytes)
    assert head["state"] == "terminal"
    receipt_bytes = (store / "objects" / (head["receipt_sha256"] + ".json")).read_bytes()
    assert hashlib.sha256(receipt_bytes).hexdigest() == head["receipt_sha256"]
    receipt = json.loads(receipt_bytes)
    assert receipt["generation"] == head["generation"]
    assert receipt["outcome"] == "clean" and receipt["native_exit"] == 0
    assert receipt["component_count"] == 104
    assert (
        datetime.fromisoformat(receipt["started_at"])
        <= datetime.fromisoformat(receipt["produced_at"])
        <= datetime.now(UTC)
    )
    for name in ("audit_sha256", "stdout_sha256", "stderr_sha256"):
        data = (store / "objects" / (receipt[name] + ".json")).read_bytes()
        assert hashlib.sha256(data).hexdigest() == receipt[name]
    actual_audit = (SOURCE / ".tool-cache/security/pip-audit.json").read_bytes()
    assert hashlib.sha256(actual_audit).hexdigest() == receipt["audit_sha256"]
    assert len(json.loads(actual_audit)["dependencies"]) == 104
    (root / ".tool-cache/security/pip-audit.json").write_bytes(actual_audit)
    before = snapshots(root)
    first = run_guard("dependency_alignment", root)
    second = run_guard("dependency_alignment", root)
    payload(first, 0)
    payload(second, 0)
    assert first.stdout == second.stdout and snapshots(root) == before
    assert (store / "HEAD.json").read_bytes() == head_bytes


def test_foreign_root_cannot_run_or_admit_a_producer(root: Path) -> None:
    """A received repository cannot start production or create its own trusted store."""
    before = snapshots(root)
    store = SOURCE / ".tool-cache/security-admissions/HEAD.json"
    previous = store.read_bytes() if store.exists() else None
    result = run_guard("dependency_alignment", root, "--produce-audit")
    record = payload(result, 2)
    assert record["scope"] == "audit_produce"
    assert snapshots(root) == before
    assert not (root / ".tool-cache/security-admissions").exists()
    assert (store.read_bytes() if store.exists() else None) == previous


def test_repeated_producer_option_is_invalid_before_admission(root: Path) -> None:
    """A repeated explicit write operation refuses safely without starting an attempt."""
    result = run_guard("dependency_alignment", root, "--produce-audit", "--produce-audit")
    payload(result, 4)
    assert not (root / ".tool-cache/security-admissions").exists()


@pytest.mark.parametrize(
    ("source", "expected", "reason"),
    [
        ("requirements-dev.txt", 2, "dependency_alignment.missing-hash"),
        ("dependency-provenance.json", 2, "dependency_alignment.licence-drift"),
        ("historical-time", 4, "configuration_invalid"),
    ],
)
def test_changed_producer_inputs_preserve_entire_prior_admission(
    audited_clone: Path, source: str, expected: int, reason: str
) -> None:
    """Refuse original input drift before a pending generation, cache or native audit exists."""
    store = audited_clone / ".tool-cache/security-admissions"
    before = {
        str(path.relative_to(store)): path.read_bytes()
        for path in store.rglob("*")
        if path.is_file()
    }
    received = audited_clone / ".tool-cache/security/pip-audit.json"
    received_before = received.read_bytes()
    if source == "historical-time":
        provenance = audited_clone / "dependency-provenance.json"
        value = json.loads(provenance.read_bytes())
        value["security_audit"]["produced_at"] = "invalid-original-time"
        provenance.write_text(json.dumps(value) + "\n")
    else:
        with (audited_clone / source).open("ab") as stream:
            stream.write(b"\n")
    result = payload(clone_dependency(audited_clone, "--produce-audit"), expected)
    assert result["scope"] == "audit_produce"
    assert reason in str(result["reasons"])
    assert "unexpected_fault" not in str(result["reasons"])
    after = {
        str(path.relative_to(store)): path.read_bytes()
        for path in store.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert received.read_bytes() == received_before
    assert not list(store.glob("http-*"))


@pytest.mark.parametrize(
    ("case", "fault", "expected", "reason"),
    [
        ("cache-mkdir", "mkdirat:error=EIO", 2, "output_failure"),
        ("subreaper-denied", "prctl:error=EPERM", 3, "tool_unavailable"),
        ("interrupt", "prctl:signal=SIGINT", 3, "interrupted"),
        ("terminate", "prctl:signal=SIGTERM", 3, "interrupted"),
    ],
)
def test_public_producer_native_startup_failures_retain_attempt(
    audited_clone: Path,
    tmp_path: Path,
    actual_strace: Path,
    case: str,
    fault: str,
    expected: int,
    reason: str,
) -> None:
    """Retain a genuine terminal or pending attempt after actual native startup failure."""
    store = audited_clone / ".tool-cache/security-admissions"
    script = audited_clone / "tools/check_dependency_alignment.py"
    baseline_trace = tmp_path / "producer-baseline.native-trace"
    command = source_python(str(script), "--root", str(audited_clone), "--produce-audit", "--json")
    baseline = subprocess.run(
        [
            str(actual_strace),
            "-f",
            "-qq",
            "--kill-on-exit",
            "-yy",
            "-s",
            "1024",
            "-o",
            str(baseline_trace),
            "-e",
            "trace=prctl,mkdirat",
            *command,
        ],
        cwd=audited_clone,
        capture_output=True,
        timeout=120,
    )
    payload(baseline, 0)
    prior_head = (store / "HEAD.json").read_bytes()
    prior = json.loads(prior_head)
    prior_receipt = json.loads(
        (store / "objects" / (prior["receipt_sha256"] + ".json")).read_bytes()
    )
    assert prior_receipt["outcome"] == "clean" and prior_receipt["component_count"] == 104
    original_objects = {p.name: p.read_bytes() for p in (store / "objects").iterdir()}
    original_audit = (audited_clone / ".tool-cache/security/pip-audit.json").read_bytes()
    old_caches = {p.name for p in store.glob("http-*")}
    source_before = snapshots(audited_clone)
    syscall = fault.partition(":")[0]
    lines = baseline_trace.read_bytes().splitlines()
    marker = b'"http-' if case == "cache-mkdir" else b"prctl(PR_SET_CHILD_SUBREAPER, 1)"
    matched = next(line for line in lines if marker in line)
    parent = matched.split(maxsplit=1)[0]
    calls = [
        line
        for line in lines
        if line.split(maxsplit=1)[0] == parent
        and line.split(maxsplit=1)[1].startswith(syscall.encode() + b"(")
    ]
    ordinal = calls.index(matched) + 1
    trace = tmp_path / (case + ".native-trace")
    result = subprocess.run(
        [
            str(actual_strace),
            "-f",
            "-qq",
            "--kill-on-exit",
            "-yy",
            "-s",
            "1024",
            "-o",
            str(trace),
            "-e",
            "trace=prctl,mkdirat",
            "-e",
            "inject=" + fault + ":when=" + str(ordinal),
            *command,
        ],
        cwd=audited_clone,
        capture_output=True,
        timeout=120,
    )
    report = payload(result, expected)
    assert report["scope"] == "audit_produce" and reason in str(report["reasons"])
    assert "unexpected_fault" not in str(report["reasons"])
    assert snapshots(audited_clone) == source_before
    assert (audited_clone / ".tool-cache/security/pip-audit.json").read_bytes() == original_audit
    for name, data in original_objects.items():
        assert (store / "objects" / name).read_bytes() == data
    head = json.loads((store / "HEAD.json").read_bytes())
    assert head["generation"] != prior["generation"]
    caches = {p.name for p in store.glob("http-*")}
    if case == "cache-mkdir":
        assert head["state"] == "pending" and head["receipt_sha256"] is None
        assert caches == old_caches
    else:
        assert head["state"] == "terminal" and len(caches - old_caches) == 1
        selector = head["receipt_sha256"]
        receipt_bytes = (store / "objects" / (selector + ".json")).read_bytes()
        assert hashlib.sha256(receipt_bytes).hexdigest() == selector
        receipt = json.loads(receipt_bytes)
        assert receipt["generation"] == head["generation"]
        assert receipt["outcome"] == "unavailable"
        assert receipt["native_exit"] is None and receipt["produced_at"] is None
        assert receipt["component_count"] == 0 and receipt["audit_sha256"] is None
        for field in ["stdout_sha256", "stderr_sha256"]:
            assert (store / "objects" / (receipt[field] + ".json")).read_bytes() == b""
    actual = trace.read_bytes()
    if ":error=" in fault:
        assert b"INJECTED" in actual
    else:
        assert (b"SIGINT" if case == "interrupt" else b"SIGTERM") in actual
    consumer = payload(clone_dependency(audited_clone), 3)
    assert "unexpected_fault" not in str(consumer["reasons"])
    assert (store / "HEAD.json").read_bytes() != prior_head


def test_public_producer_real_exec_denial_retains_unavailable_attempt(
    audited_clone: Path,
) -> None:
    """A process-local kernel exec denial cannot turn an absent audit child into success."""
    store = audited_clone / ".tool-cache/security-admissions"
    previous = (store / "HEAD.json").read_bytes()
    audit_bytes = (audited_clone / ".tool-cache/security/pip-audit.json").read_bytes()
    program = """import ctypes,runpy,sys
class Filter(ctypes.Structure):
    _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
filters=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,59),Filter(0x06,0,0,0x5000d),Filter(0x06,0,0,0x7fff0000))
filter_program=Program(4,filters)
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0
assert libc.prctl(22,2,ctypes.byref(filter_program),0,0)==0
sys.path.insert(0,sys.argv[1])
script=sys.argv[2]
sys.argv=[script,'--root',sys.argv[3],'--produce-audit','--json']
runpy.run_path(script,run_name='__main__')
"""
    result = subprocess.run(
        source_python(
            "-I",
            "-B",
            "-c",
            program,
            str(audited_clone / "tools"),
            str(audited_clone / "tools/check_dependency_alignment.py"),
            str(audited_clone),
        ),
        cwd=audited_clone,
        capture_output=True,
        timeout=120,
    )
    report = payload(result, 3)
    assert report["scope"] == "audit_produce" and "tool_unavailable" in str(report["reasons"])
    assert "unexpected_fault" not in str(report["reasons"])
    head_bytes = (store / "HEAD.json").read_bytes()
    assert head_bytes != previous
    head = json.loads(head_bytes)
    assert head["state"] == "terminal"
    selector = head["receipt_sha256"]
    receipt_bytes = (store / "objects" / (selector + ".json")).read_bytes()
    assert hashlib.sha256(receipt_bytes).hexdigest() == selector
    receipt = json.loads(receipt_bytes)
    assert receipt["generation"] == head["generation"] and receipt["outcome"] == "unavailable"
    assert receipt["native_exit"] is None and receipt["produced_at"] is None
    assert receipt["component_count"] == 0 and receipt["audit_sha256"] is None
    assert (audited_clone / ".tool-cache/security/pip-audit.json").read_bytes() == audit_bytes
    payload(clone_dependency(audited_clone), 3)
    assert (store / "HEAD.json").read_bytes() == head_bytes


@pytest.mark.parametrize("stage", ["before-native", "before-publication"])
def test_public_producer_genuine_deadline_retains_unavailable_attempt(
    audited_clone: Path, tmp_path: Path, actual_strace: Path, stage: str
) -> None:
    """Enforce the real unchanged inclusive120second budget before exec or publication."""
    import time

    from local_scaffold.policy import LEAF_SECONDS

    store = audited_clone / ".tool-cache/security-admissions"
    script = audited_clone / "tools/check_dependency_alignment.py"
    command = source_python(str(script), "--root", str(audited_clone), "--produce-audit", "--json")
    baseline_trace = tmp_path / "deadline-baseline.native-trace"
    baseline = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "--kill-on-exit",
            "-yy",
            "-s",
            "1024",
            "-o",
            str(baseline_trace),
            "-e",
            "trace=fsync",
            *command,
        ],
        cwd=audited_clone,
        capture_output=True,
        timeout=120,
    )
    payload(baseline, 0)
    before = (store / "HEAD.json").read_bytes()
    previous = json.loads(before)
    original_audit = (audited_clone / ".tool-cache/security/pip-audit.json").read_bytes()
    objects = {p.name: p.read_bytes() for p in (store / "objects").iterdir()}
    calls = [
        line for line in baseline_trace.read_bytes().splitlines() if line.startswith(b"fsync(")
    ]
    marker = b"/security-admissions/.audit-" if stage == "before-native" else b"/objects/.audit-"
    ordinal = next(index for index, line in enumerate(calls, start=1) if marker in line)
    trace = tmp_path / (stage + ".native-trace")
    started = time.monotonic()
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "--kill-on-exit",
            "-yy",
            "-s",
            "1024",
            "-o",
            str(trace),
            "-e",
            "trace=fsync",
            "-e",
            "inject=fsync:delay_exit=" + str(int(LEAF_SECONDS) + 1) + "s:when=" + str(ordinal),
            *command,
        ],
        cwd=audited_clone,
        capture_output=True,
        timeout=160,
    )
    assert time.monotonic() - started >= LEAF_SECONDS
    report = payload(result, 3)
    assert report["scope"] == "audit_produce" and "tool_timeout" in str(report["reasons"])
    assert "unexpected_fault" not in str(report["reasons"])
    delayed = [line for line in trace.read_bytes().splitlines() if b"DELAYED" in line]
    assert len(delayed) == 1 and marker in delayed[0]
    head_bytes = (store / "HEAD.json").read_bytes()
    assert head_bytes != before
    head = json.loads(head_bytes)
    assert head["state"] == "terminal" and head["generation"] != previous["generation"]
    selector = head["receipt_sha256"]
    receipt_bytes = (store / "objects" / (selector + ".json")).read_bytes()
    assert hashlib.sha256(receipt_bytes).hexdigest() == selector
    receipt = json.loads(receipt_bytes)
    assert receipt["outcome"] == "unavailable" and receipt["generation"] == head["generation"]
    if stage == "before-native":
        assert receipt["native_exit"] is None and receipt["produced_at"] is None
        assert receipt["component_count"] == 0 and receipt["audit_sha256"] is None
    else:
        assert receipt["native_exit"] == 0 and receipt["produced_at"] is not None
        assert receipt["component_count"] == 104
        assert receipt["audit_sha256"] == receipt["stdout_sha256"]
        actual_audit = (store / "objects" / (receipt["audit_sha256"] + ".json")).read_bytes()
        assert len(json.loads(actual_audit)["dependencies"]) == 104
    assert (audited_clone / ".tool-cache/security/pip-audit.json").read_bytes() == original_audit
    for name, data in objects.items():
        assert (store / "objects" / name).read_bytes() == data
    payload(clone_dependency(audited_clone), 3)
    assert (store / "HEAD.json").read_bytes() == head_bytes
