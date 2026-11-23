# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual store files, no-follow boundaries and kernel lock contention."""

import fcntl
import json
import os
import subprocess
from pathlib import Path

import pytest

from local_scaffold.policy import MAX_INPUT
from tests.conftest import clone_dependency, payload, source_python
from tests.test_atomic_publication import actual_strace as actual_strace


@pytest.mark.parametrize("name", ["HEAD.json", "admission.lock", "objects"])
def test_missing_store_input_is_unavailable(audited_clone: Path, name: str) -> None:
    """Missing authored native resources remain unavailable, preserving their originals."""
    store = audited_clone / ".tool-cache/security-admissions"
    (store / name).rename(store / (name + ".preserved"))
    payload(clone_dependency(audited_clone), 3)


@pytest.mark.parametrize("name", ["HEAD.json", "admission.lock", "objects"])
@pytest.mark.parametrize("produce", [False, True])
def test_store_symlinks_refuse_without_touching_target(
    audited_clone: Path, name: str, produce: bool
) -> None:
    """A linked store component cannot redirect reads or native producer writes."""
    store = audited_clone / ".tool-cache/security-admissions"
    original = store / (name + ".preserved")
    (store / name).rename(original)
    (store / name).symlink_to(original, target_is_directory=name == "objects")
    payload(clone_dependency(audited_clone, *(["--produce-audit"] if produce else [])), 2)
    assert original.exists()
    assert not list(store.glob("http-*"))


_ADMISSIONS = ".tool-cache/security-admissions"
"""The admission store's directory, which the store opens without following a link."""
_INPUTS = ".tool-cache/environment-inputs"
"""The local packages' inputs, whose base is refused under a linked ancestor."""


@pytest.mark.parametrize(
    ("name", "produce", "code", "location"),
    [
        (".tool-cache", False, "repository_inventory.symlink-entry", _INPUTS),
        (".tool-cache", True, "repository_inventory.symlink-entry", _INPUTS),
        (_ADMISSIONS, False, "policy_refusal", _ADMISSIONS),
        (_ADMISSIONS, True, "policy_refusal", _ADMISSIONS),
    ],
)
def test_linked_store_directories_refuse_without_touching_target(
    audited_clone: Path, name: str, produce: bool, code: str, location: str
) -> None:
    """A linked tool cache or admission directory cannot redirect the store or its producer.

    The store opens every component from the root without following a link, so it
    refuses the link itself, before any read of foreign objects or any producer write;
    the local package check refuses a linked tool cache as a symbolic ancestor of its
    inputs before the store is reached.
    Each refusal is the only reason, and the linked target keeps exactly its entries.
    The Make target has no guard of its own: the store owns this boundary.
    """
    linked = audited_clone / name
    original = linked.with_name(linked.name + ".preserved")
    linked.rename(original)
    linked.symlink_to(original, target_is_directory=True)
    before = sorted(str(path.relative_to(original)) for path in original.rglob("*"))
    value = payload(clone_dependency(audited_clone, *(["--produce-audit"] if produce else [])), 2)
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert [
        (reason["code"], reason["location"]) for reason in reasons if isinstance(reason, dict)
    ] == [(code, location)]
    assert sorted(str(path.relative_to(original)) for path in original.rglob("*")) == before
    assert linked.is_symlink()


@pytest.mark.parametrize("name", ["HEAD.json", "admission.lock"])
@pytest.mark.parametrize("produce", [False, True])
def test_store_fifo_is_refused_without_blocking(
    audited_clone: Path, name: str, produce: bool
) -> None:
    """A real native FIFO cannot block a regular-file admission read or lease."""
    store = audited_clone / ".tool-cache/security-admissions"
    (store / name).rename(store / (name + ".preserved"))
    os.mkfifo(store / name)
    payload(clone_dependency(audited_clone, *(["--produce-audit"] if produce else [])), 2)
    assert not list(store.glob("http-*"))


@pytest.mark.parametrize("name", ["HEAD.json", "admission.lock", "objects"])
@pytest.mark.parametrize("produce", [False, True])
def test_wrong_store_component_kind_refuses(audited_clone: Path, name: str, produce: bool) -> None:
    """File-for-directory and directory-for-file substitutions refuse before production."""
    store = audited_clone / ".tool-cache/security-admissions"
    original = store / (name + ".preserved")
    (store / name).rename(original)
    if name == "objects":
        (store / name).write_bytes(b"not a directory")
    else:
        (store / name).mkdir()
    payload(clone_dependency(audited_clone, *(["--produce-audit"] if produce else [])), 2)
    assert original.exists()
    assert not list(store.glob("http-*"))


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_immutable_object_special_kinds_refuse(audited_clone: Path, kind: str) -> None:
    """An immutable digest selector never follows a link or blocks on a special file."""
    store = audited_clone / ".tool-cache/security-admissions"
    head = json.loads((store / "HEAD.json").read_bytes())
    path = store / "objects" / (head["receipt_sha256"] + ".json")
    original = path.with_suffix(".preserved")
    path.rename(original)
    if kind == "symlink":
        path.symlink_to(original)
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    payload(clone_dependency(audited_clone), 2)
    assert original.is_file()


def test_oversized_head_refuses_without_reading_unbounded_bytes(audited_clone: Path) -> None:
    """The native fixed-head byte budget is enforced before JSON or receipt admission."""
    head = audited_clone / ".tool-cache/security-admissions/HEAD.json"
    with head.open("wb") as stream:
        stream.truncate(MAX_INPUT + 1)
    result = payload(clone_dependency(audited_clone), 2)
    assert "resource_limit" in str(result["reasons"])


def test_native_write_limit_preserves_prior_head(audited_clone: Path) -> None:
    """A real kernel file-size refusal retains prior objects and cannot publish success."""
    store = audited_clone / ".tool-cache/security-admissions"
    before = (store / "HEAD.json").read_bytes()
    object_names = set(path.name for path in (store / "objects").iterdir())
    program = """import resource,runpy,sys
limits=resource.getrlimit(resource.RLIMIT_FSIZE)
resource.setrlimit(resource.RLIMIT_FSIZE,(0,limits[1]))
try:
    sys.argv=[sys.argv[1],'--root',sys.argv[2],'--produce-audit','--json']
    sys.path.insert(0,sys.argv[0].rsplit('/',1)[0])
    runpy.run_path(sys.argv[0],run_name='__main__')
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE,limits)
"""
    result = subprocess.run(
        source_python(
            "-B",
            "-c",
            program,
            str(audited_clone / "tools/check_dependency_alignment.py"),
            str(audited_clone),
        ),
        cwd=audited_clone,
        capture_output=True,
        timeout=120,
    )
    observed = payload(result, 2)
    assert "output_failure" in str(observed["reasons"])
    assert (store / "HEAD.json").read_bytes() == before
    assert set(path.name for path in (store / "objects").iterdir()) == object_names
    assert list(store.glob(".audit-*"))
    assert not list(store.glob("http-*"))


def test_changed_immutable_receipt_bytes_refuse(audited_clone: Path) -> None:
    """Changing bytes under their original digest filename is an identity refusal."""
    store = audited_clone / ".tool-cache/security-admissions"
    head = json.loads((store / "HEAD.json").read_bytes())
    path = store / "objects" / (head["receipt_sha256"] + ".json")
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    payload(clone_dependency(audited_clone), 2)


@pytest.mark.parametrize(
    ("exclusive", "produce", "expected"),
    [(True, False, 3), (False, False, 2), (True, True, 3), (False, True, 3)],
)
def test_real_shared_and_exclusive_admission_leases(
    audited_clone: Path, exclusive: bool, produce: bool, expected: int
) -> None:
    """Actual kernel contention refuses without creating a generation or network child."""
    store = audited_clone / ".tool-cache/security-admissions"
    original = (store / "HEAD.json").read_bytes()
    with (store / "admission.lock").open("rb") as lock:
        fcntl.flock(lock.fileno(), (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        payload(
            clone_dependency(audited_clone, *(["--produce-audit"] if produce else [])), expected
        )
        assert (store / "HEAD.json").read_bytes() == original
        assert not list(store.glob("http-*"))
    payload(clone_dependency(audited_clone), 2)


def test_public_store_round_trip_and_replacement(tmp_path: Path) -> None:
    """Publish exact source bytes through all documented store methods and close leases."""
    from local_scaffold.audit_store import open_store
    from tests.conftest import SOURCE

    installation = tmp_path / "installation"
    installation.mkdir()
    original = (SOURCE / "README.md").read_bytes()
    replacement = (SOURCE / "CITATION.cff").read_bytes()
    with open_store(installation, write=True) as store:
        digest = store.object(original)
        assert store.object(original) == digest
        assert store.read(digest, object_file=True) == original
        store.publish_head(original)
        assert store.read("HEAD.json") == original
        store.publish_head(replacement)
        assert store.read("HEAD.json") == replacement
        store.publish_audit(original)
        store.publish_audit(replacement)
        descriptors = (store.root, store.cache, store.directory, store.objects)
    assert (installation / ".tool-cache/security/pip-audit.json").read_bytes() == replacement
    assert (installation / ".tool-cache/security-admissions/HEAD.json").read_bytes() == replacement
    assert not list(installation.rglob(".audit-*"))
    for descriptor in descriptors:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)
    with open_store(installation) as store:
        assert store.read("HEAD.json") == replacement
        assert store.read(digest, object_file=True) == original


@pytest.mark.parametrize(
    ("name", "object_file"),
    [("../HEAD.json", False), ("head.json", False), ("A" * 64, True), ("a" * 63, True)],
)
def test_public_store_selector_refusal_preserves_source(
    tmp_path: Path, name: str, object_file: bool
) -> None:
    """Reject received selectors before opening any object or following a received path."""
    from local_scaffold.audit_store import open_store
    from local_scaffold.reports import Fault
    from tests.conftest import SOURCE

    installation = tmp_path / "installation"
    installation.mkdir()
    original = (SOURCE / "README.md").read_bytes()
    with open_store(installation, write=True) as store:
        digest = store.object(original)
        store.publish_head(original)
        with pytest.raises(Fault) as observed:
            store.read(name, object_file=object_file)
        assert (observed.value.code, observed.value.exit_code) == ("configuration_invalid", 4)
        assert store.read("HEAD.json") == original
        assert store.read(digest, object_file=True) == original
    assert not list(installation.rglob(".audit-*"))


def test_public_store_native_zero_write_retains_prior_head(
    tmp_path: Path, actual_strace: Path
) -> None:
    """A native zero-byte write refuses publication and retains the owned failed temporary."""
    from local_scaffold.audit_store import open_store
    from tests.conftest import SOURCE

    original = (SOURCE / "README.md").read_bytes()
    for name in ["baseline", "zero-write"]:
        installation = tmp_path / name
        installation.mkdir()
        with open_store(installation, write=True) as store:
            store.publish_head(original)

    program = """import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.audit_store import open_store
from local_scaffold.reports import Fault
root=Path(sys.argv[2])
original=Path(sys.argv[3]).read_bytes()
try:
    with open_store(root,write=True) as store:
        digest=store.object(original)
    print(json.dumps({'digest':digest}))
except Fault as fault:
    print(json.dumps({'code':fault.code,'exit_code':fault.exit_code}))
    sys.exit(fault.exit_code)
"""
    trace = tmp_path / "baseline.native-trace"
    baseline = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=write",
            *source_python(
                "-I",
                "-B",
                "-c",
                program,
                str(SOURCE / "tools"),
                str(tmp_path / "baseline"),
                str(SOURCE / "README.md"),
            ),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert baseline.returncode == 0 and not baseline.stderr
    writes = [line for line in trace.read_bytes().splitlines() if line.startswith(b"write(")]
    ordinal = next(index for index, line in enumerate(writes, start=1) if b"/.audit-" in line)
    failed = tmp_path / "zero-write"
    fault_trace = tmp_path / "zero-write.native-trace"
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(fault_trace),
            "-e",
            "trace=write",
            "-e",
            "inject=write:retval=0:when=" + str(ordinal),
            *source_python(
                "-I",
                "-B",
                "-c",
                program,
                str(SOURCE / "tools"),
                str(failed),
                str(SOURCE / "README.md"),
            ),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2 and not result.stderr, (result.stdout, result.stderr)
    assert json.loads(result.stdout) == {"code": "output_failure", "exit_code": 2}
    injected = [line for line in fault_trace.read_bytes().splitlines() if b"INJECTED" in line]
    assert len(injected) == 1 and b"/.audit-" in injected[0] and b"= 0 (INJECTED)" in injected[0]
    objects = failed / ".tool-cache/security-admissions/objects"
    temporaries = list(objects.glob(".audit-*"))
    assert len(temporaries) == 1 and temporaries[0].read_bytes() == b""
    assert not list(objects.glob("*.json"))
    assert (failed / ".tool-cache/security-admissions/HEAD.json").read_bytes() == original


@pytest.mark.parametrize("case", ["short-read", "changed-bytes", "growth-budget", "head-replaced"])
def test_public_store_native_read_and_publication_changes(
    tmp_path: Path, actual_strace: Path, case: str
) -> None:
    """Refuse actual short reads and source changes between anchored native operations."""
    import signal
    import time

    from local_scaffold.audit_store import open_store
    from tests.conftest import SOURCE

    source = (SOURCE / "README.md").read_bytes()
    original = (
        (source * (MAX_INPUT // len(source) + 1))[:MAX_INPUT] if case == "growth-budget" else source
    )
    replacement = (SOURCE / "CITATION.cff").read_bytes()
    for name in ["baseline", "changed"]:
        installation = tmp_path / name
        installation.mkdir()
        with open_store(installation, write=True) as store:
            store.publish_head(original)
    program = """import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.audit_store import open_store
from local_scaffold.reports import Fault
root=Path(sys.argv[2]);case=sys.argv[3]
Path(sys.argv[4]).write_text(str(os.getpid()))
try:
    with open_store(root,write=case=='head-replaced') as store:
        if case=='head-replaced':
            store.publish_head(Path(sys.argv[5]).read_bytes())
            result={'published':True}
        else:
            data=store.read('HEAD.json')
            result={'read_bytes':len(data)}
    print(json.dumps(result))
except Fault as fault:
    print(json.dumps({'code':fault.code,'exit_code':fault.exit_code}))
    sys.exit(fault.exit_code)
"""
    syscall = "newfstatat" if case == "head-replaced" else "read"
    trace = tmp_path / "baseline.native-trace"
    command = source_python(
        "-I",
        "-B",
        "-c",
        program,
        str(SOURCE / "tools"),
        str(tmp_path / "baseline"),
        case,
        str(tmp_path / "baseline.ready"),
        str(SOURCE / "CITATION.cff"),
    )
    baseline = subprocess.run(
        [
            str(actual_strace),
            "-f",
            "-qq",
            "--kill-on-exit",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=" + syscall,
            *command,
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert baseline.returncode == 0 and not baseline.stderr, (baseline.stdout, baseline.stderr)
    assert json.loads(baseline.stdout) == (
        {"published": True} if case == "head-replaced" else {"read_bytes": len(original)}
    )
    calls = [
        line
        for line in trace.read_bytes().splitlines()
        if line.split(maxsplit=1)[1].startswith(syscall.encode() + b"(")
    ]
    matches = [
        (index, line)
        for index, line in enumerate(calls, start=1)
        if (
            b"/security-admissions/HEAD.json>" in line
            or (b"/security-admissions>" in line and b'"HEAD.json"' in line)
        )
    ]
    ordinal = matches[0][0]
    assert len(matches) == (
        2 if case == "head-replaced" else len(original) // 65536 + 1 + (len(original) % 65536 != 0)
    )
    installation = tmp_path / "changed"
    head = installation / ".tool-cache/security-admissions/HEAD.json"
    ready = tmp_path / "changed.ready"
    fault_trace = tmp_path / "changed.native-trace"
    fault = syscall + (":retval=0" if case == "short-read" else ":signal=SIGSTOP")
    process = subprocess.Popen(
        [
            str(actual_strace),
            "-f",
            "-qq",
            "--kill-on-exit",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(fault_trace),
            "-e",
            "trace=" + syscall,
            "-e",
            "inject=" + fault + ":when=" + str(ordinal),
            *source_python(
                "-I",
                "-B",
                "-c",
                program,
                str(SOURCE / "tools"),
                str(installation),
                case,
                str(ready),
                str(SOURCE / "CITATION.cff"),
            ),
        ],
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        if case != "short-read":
            deadline = time.monotonic() + 10
            while True:
                lines = fault_trace.read_bytes().splitlines() if fault_trace.exists() else []
                if ready.exists() and any(
                    b"SIGSTOP" in line and b"SI_KERNEL" in line for line in lines
                ):
                    tracee = int(ready.read_text())
                    break
                assert process.poll() is None, lines
                assert time.monotonic() < deadline, (
                    "Original store syscall did not reach the native stop."
                )
                time.sleep(0.001)
            if case == "growth-budget":
                with head.open("ab") as stream:
                    stream.write(b"\n")
            elif case == "head-replaced":
                head.rename(head.with_suffix(".retained"))
                head.write_bytes(original + b"\n")
            else:
                head.write_bytes(original[::-1])
            os.kill(tracee, signal.SIGCONT)
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 2 and not stderr, (stdout, stderr)
        reason = "resource_limit" if case == "growth-budget" else "source_identity_mismatch"
        assert json.loads(stdout) == {"code": reason, "exit_code": 2}
        actual = fault_trace.read_bytes()
        if case == "short-read":
            assert b"INJECTED" in actual
            assert b"= 0 (INJECTED)" in actual
            assert head.read_bytes() == original
        else:
            assert b"SIGSTOP" in actual and b"SIGCONT" in actual
            if case == "growth-budget":
                assert head.read_bytes() == original + b"\n"
            elif case == "head-replaced":
                assert head.with_suffix(".retained").read_bytes() == original
                assert head.read_bytes() == original + b"\n"
                retained = list(head.parent.glob(".audit-*"))
                assert len(retained) == 1 and retained[0].read_bytes() == replacement
            else:
                assert head.read_bytes() == original[::-1]
    finally:
        process.kill()
        process.communicate(timeout=3)
