# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check native ownership, immutable asset provenance and real REUSE output."""

import hashlib
import json
import math
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

from local_scaffold.limits import MAX_CAPTURE
from local_scaffold.provenance import analyse_reuse
from local_scaffold.reports import Fault
from tests.conftest import (
    SOURCE,
    change,
    payload,
    poll_until,
    run_guard,
    snapshots,
    source_python,
    stop,
)
from tests.test_atomic_publication import actual_strace as actual_strace


@pytest.mark.parametrize(
    "case",
    [
        "spdx",
        "conflict",
        "notice",
        "sidecar",
        "copyright",
        "asset",
        "licence",
        "generated",
        "visible",
        "reuse",
        "sidecar-link",
        "license-notice",
        "json-conflict",
        "producer-provenance",
    ],
)
def test_real_ownership_refusals(root: Path, case: str) -> None:
    """Alter real owned bytes or kinds and inspect the actual public refusal."""
    path = root / "tools/check_repository_metadata.py"
    if case == "spdx":
        path.write_text("\n".join(path.read_text().splitlines()[1:]) + "\n")
    elif case == "conflict":
        path.write_text(path.read_text() + "\n# SPDX-License-Identifier" + ": MIT\n")
    elif case == "notice":
        path.write_text(path.read_text().replace("SPIKE-LOG —", "FOREIGN-REPOSITORY —"))
    elif case == "sidecar":
        (root / "repository-domain.json.license").unlink()
    elif case == "copyright":
        side = root / "repository-domain.json.license"
        side.write_text(
            "\n".join(s for s in side.read_text().splitlines() if "(concepts)" not in s) + "\n"
        )
    elif case == "asset":
        (root / "docs/assets/anulum_logo_company.jpg").write_bytes(b"changed actual asset")
    elif case == "licence":
        (root / "LICENSE").write_text("AGPL-3.0-or-later\n")
    elif case == "generated":
        change(root, "capability-inventory.json", ("source_metadata", "sha256"), "0" * 64)
    elif case == "visible":
        path = root / "README.md"
        path.write_text(path.read_text().replace("<!--\n", "", 1).replace("\n-->", "", 1))
    elif case == "sidecar-link":
        path = root / "repository-domain.json.license"
        path.unlink()
        path.symlink_to(root / "capability-inventory.json.license")
    elif case == "license-notice":
        path = root / "repository-domain.json.license"
        path.write_text(path.read_text().replace("Concepts 1996", "Concepts 1997"))
    elif case == "json-conflict":
        change(root, "repository-domain.json", ("spdx_license_identifier",), "MIT")
    elif case == "producer-provenance":
        change(root, "dependency-provenance.json", ("packages",), [])
    else:
        (root / "foreign.bin").write_bytes(b"actual unlicensed source")
        (root / "REUSE.toml").write_text("version = 1\n")
    report = payload(run_guard("source_provenance", root), 2)
    if case in ("asset", "notice", "license-notice", "json-conflict", "producer-provenance"):
        reasons = report["reasons"]
        assert isinstance(reasons, list)
        expected = {
            "asset": "source_provenance.third-party",
            "notice": "source_provenance.wrong-notice",
            "license-notice": "source_provenance.wrong-notice",
            "json-conflict": "source_provenance.conflicting-spdx",
            "producer-provenance": "source_provenance.third-party",
        }[case]
        assert any(isinstance(reason, dict) and reason["code"] == expected for reason in reasons)


def test_complete_provenance_is_readonly(root: Path) -> None:
    """Repeat the complete real licence gate without altering owned bytes."""
    before = snapshots(root)
    a = run_guard("source_provenance", root)
    b = run_guard("source_provenance", root)
    payload(a, 0)
    assert a.stdout == b.stdout
    assert snapshots(root) == before


def test_diagnostic_budget(root: Path) -> None:
    """A real large faulty owned tree stops at the fixed final diagnostic."""
    for i in range(260):
        (root / f"unlicensed_{i:03d}.txt").write_text("no native header\n")
    value = payload(run_guard("source_provenance", root), 2)
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert len(reasons) == 256
    assert isinstance(reasons[-1], dict)
    assert reasons[-1]["code"] == "diagnostic_budget_exceeded"


def test_private_documentation_is_outside_provenance_scope(root: Path) -> None:
    """The attribution leaf leaves genuinely ignored private inputs untouched."""
    directory = root / "docs/internal"
    directory.mkdir(exist_ok=True)
    path = directory / "private-input.txt"
    path.write_text("Confidential finite input outside published source ownership.\n")
    before = snapshots(root)
    payload(run_guard("source_provenance", root), 0)
    assert snapshots(root) == before


def test_original_unused_license_cannot_pass(root: Path) -> None:
    """An unassigned original producer license is refused by genuine REUSE output."""
    original = SOURCE / ".venv/lib/python3.13/site-packages/attrs-26.1.0.dist-info/licenses/LICENSE"
    assert not original.is_symlink()
    raw = original.read_bytes()
    assert len(raw) == 1109
    assert hashlib.sha256(raw).hexdigest() == (
        "882115c95dfc2af1eeb6714f8ec6d5cbcabf667caff8729f42420da63f714e9f"
    )
    (root / "LICENSES/MIT.txt").write_bytes(raw)
    before = snapshots(root)
    report = payload(run_guard("source_provenance", root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "source_provenance.reuse-invalid"
        for reason in reasons
    )
    assert snapshots(root) == before


@pytest.mark.parametrize("kind", ["module", "package"])
def test_received_REUSE_module_cannot_execute(root: Path, kind: str) -> None:
    """Received Python modules remain data while the genuine installed licence tool runs."""
    header = "\n".join((SOURCE / "tools/check_source_provenance.py").read_text().splitlines()[:7])
    received = (
        header
        + '\n\n"""Received local module must remain inert."""\n'
        + "from pathlib import Path\n"
        + "Path('received-execution-marker').write_bytes(b'actual received execution')\n"
    )
    if kind == "module":
        (root / "reuse.py").write_text(received)
    else:
        directory = root / "reuse"
        directory.mkdir()
        (directory / "__init__.py").write_text(received)
        (directory / "__main__.py").write_text(received)
    before = snapshots(root)
    payload(run_guard("source_provenance", root), 0)
    assert not (root / "received-execution-marker").exists()
    assert snapshots(root) == before


@pytest.mark.parametrize("explicit_git_environment", [False, True])
def test_actual_REUSE_respects_authorised_tmp_and_parent_Git_isolation(
    root: Path, tmp_path: Path, actual_strace: Path, explicit_git_environment: bool
) -> None:
    """A real ignored temp directory retains every native licence input and cleans up."""
    directory = root / ".tool-cache/owned-reuse-tmp"
    directory.mkdir()
    original_parent = subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
        capture_output=True,
        timeout=10,
        check=True,
    )
    assert Path(os.fsdecode(original_parent.stdout.strip())) == root
    header = "\n".join((SOURCE / "tools/check_source_provenance.py").read_text().splitlines()[:7])
    (root / "REUSE.toml").write_text(header + "\n\nversion = 1\n")
    (root / "received-unlicensed.txt").write_text("Actual received public unlicensed input.\n")
    ignore = root / ".gitignore"
    ignore.write_bytes(ignore.read_bytes() + b"\nreceived-unlicensed.txt\n")
    before = snapshots(root)
    program = """import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.provenance import analyse_reuse
result=analyse_reuse(Path(sys.argv[2]))
sys.stdout.buffer.write(result.stdout)
sys.exit(result.exit_code)
"""
    trace = tmp_path / "actual_REUSE_authorised_tmp.native-trace"
    parent_environment = dict(os.environ)
    child_environment = {
        **os.environ,
        "TMPDIR": str(directory),
        "TMP": str(directory),
        "TEMP": str(directory),
        "GIT_CEILING_DIRECTORIES": "/",
    }
    if explicit_git_environment:
        child_environment.update(GIT_DIR=str(root / ".git"), GIT_WORK_TREE=str(directory))
    result = subprocess.run(
        [
            str(actual_strace),
            "-f",
            "-qq",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=mkdir,rmdir",
            *source_python("-I", "-c", program, str(SOURCE / "tools"), str(root)),
        ],
        cwd=SOURCE,
        env=child_environment,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 1 and not result.stderr, (result.stdout, result.stderr)
    record = json.loads(result.stdout)
    name = "received-unlicensed.txt"
    assert any(file["path"] == name for file in record["files"])
    for key in ("missing_copyright_info", "missing_licensing_info"):
        assert any(path.endswith("/" + name) for path in record["non_compliant"][key])
    calls = trace.read_bytes().splitlines()
    created = [
        line
        for line in calls
        if b'mkdir("' in line and b"spike-log-reuse-" in line and b'", 0700)' in line
    ]
    assert len(created) == 1 and os.fsencode(directory) + b"/spike-log-reuse-" in created[0]
    assert any(
        b'rmdir("' in line and b"spike-log-reuse-" in line and b"= 0" in line for line in calls
    )
    assert not list(directory.iterdir())
    assert snapshots(root) == before and dict(os.environ) == parent_environment


def test_received_original_git_cannot_be_selected_by_native_REUSE(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """Real native REUSE cannot execute a received copy of the original Git binary."""
    original_binary = Path("/usr/bin/git").read_bytes()
    received = root / "git"
    received.write_bytes(original_binary)
    received.chmod(0o755)
    directory = root / ".tool-cache/received-git-reuse-tmp"
    directory.mkdir()
    before = snapshots(root)
    program = """import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.provenance import analyse_reuse
result=analyse_reuse(Path(sys.argv[2]))
sys.stdout.buffer.write(result.stdout)
sys.exit(result.exit_code)
"""
    trace = tmp_path / "native_REUSE_original_received_git.execve"
    parent_environment = dict(os.environ)
    result = subprocess.run(
        [
            str(actual_strace),
            "-f",
            "-qq",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=execve",
            *source_python("-I", "-c", program, str(SOURCE / "tools"), str(root)),
        ],
        cwd=SOURCE,
        env={
            **os.environ,
            "PATH": str(root) + os.pathsep + os.environ["PATH"],
            "TMPDIR": str(directory),
            "TMP": str(directory),
            "TEMP": str(directory),
        },
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0 and not result.stderr, (result.stdout, result.stderr)
    record = json.loads(result.stdout)
    assert any(file["path"] == "git" for file in record["files"])
    selected = b'execve("' + os.fsencode(received) + b'"'
    assert not any(selected in line for line in trace.read_bytes().splitlines())
    assert received.read_bytes() == original_binary
    assert snapshots(root) == before
    assert not list(directory.iterdir())
    assert dict(os.environ) == parent_environment


@pytest.mark.parametrize("location", ["ordinary", "nested"])
def test_git_ignored_public_license_failure_is_still_checked(root: Path, location: str) -> None:
    """Received Git ignore rules cannot conceal genuine missing native copyrights."""
    header = "\n".join((SOURCE / "tools/check_source_provenance.py").read_text().splitlines()[:7])
    directory = root if location == "ordinary" else root / "received"
    directory.mkdir(exist_ok=True)
    path = directory / "received.txt"
    path.write_text("Received public text without any copyright or licence record.\n")
    (root / "REUSE.toml").write_text(header + "\n\nversion = 1\n")
    with (root / ".gitignore").open("a") as stream:
        stream.write("\n/received.txt\n/received/\n")
    before = snapshots(root)
    native = analyse_reuse(root)
    assert native.exit_code == 1
    wire = json.loads(native.stdout)
    name = path.relative_to(root).as_posix()
    assert any(record["path"] == name for record in wire["files"])
    for key in ("missing_copyright_info", "missing_licensing_info"):
        assert any(value.endswith("/" + name) for value in wire["non_compliant"][key])
    result = payload(run_guard("source_provenance", root), 2)
    reasons = result["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "source_provenance.reuse-invalid"
        for reason in reasons
    )
    assert snapshots(root) == before


def test_nested_original_REUSE_policy_is_preserved(root: Path) -> None:
    """An original nested policy remains visible to the genuine native licence checker."""
    header = "\n".join((SOURCE / "tools/check_source_provenance.py").read_text().splitlines()[:7])
    directory = root / "received"
    directory.mkdir()
    (directory / "received.txt").write_text(header + "\n\nReceived public data.\n")
    (directory / "REUSE.toml").write_text(header + "\n\nversion = 1\n[[annotations]\n")
    before = snapshots(root)
    value = payload(run_guard("source_provenance", root), 2)
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "source_provenance.reuse-invalid"
        for reason in reasons
    )
    assert snapshots(root) == before


def test_ignored_cache_cannot_choose_nested_licensing(root: Path) -> None:
    """Ignored cached policy stays outside the complete public licence scope."""
    directory = root / ".tool-cache/received"
    directory.mkdir()
    (directory / "REUSE.toml").write_text("version = 1000000\n")
    (directory / "reuse.py").write_text("raise RuntimeError('received cache code')\n")
    original = {path.name: path.read_bytes() for path in directory.iterdir()}
    before = snapshots(root)
    payload(run_guard("source_provenance", root), 0)
    assert {path.name: path.read_bytes() for path in directory.iterdir()} == original
    assert snapshots(root) == before


@pytest.mark.parametrize("duration", [0.0, -1.0, 121.0, math.nan, math.inf, True])
def test_public_licence_budget_remains_finite(root: Path, duration: float) -> None:
    """A trusted caller cannot extend or invalidate the original licence deadline."""
    with pytest.raises(Fault) as error:
        analyse_reuse(root, duration)
    assert error.value.code == "configuration_invalid" and error.value.exit_code == 4


def test_actual_public_copy_exhausts_tiny_licence_budget(root: Path) -> None:
    """Actual copying consumes its shared budget before a producer can be started."""
    before = snapshots(root)
    with pytest.raises(Fault) as error:
        analyse_reuse(root, 0.000000001)
    assert error.value.code == "tool_timeout" and error.value.exit_code == 3
    assert snapshots(root) == before


@pytest.mark.parametrize("case", ["source-bytes", "cache-kind", "deadline"])
def test_real_native_licence_input_change_is_refused(
    root: Path, case: str, actual_strace: Path, tmp_path: Path
) -> None:
    """Trace actual native reads, input changes and a stopped post-producer deadline."""
    document = root / "VALIDATION.md"
    original = document.read_bytes()
    cache = root / ".tool-cache"
    held = root.parent / "actual-retained-original-cache"
    assert not held.exists()
    program = """import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.provenance import analyse_reuse
from local_scaffold.reports import Fault
try:
    result=analyse_reuse(Path(sys.argv[2]),float(sys.argv[3]))
    print(json.dumps({'native_exit':result.exit_code}))
except Fault as fault:
    print(json.dumps({'code':fault.code,'exit_code':fault.exit_code}))
    sys.exit(fault.exit_code)
"""
    trace = tmp_path / (case + "-licence-original-read.native-trace")
    arguments = [
        str(actual_strace),
        "-f",
        "--kill-on-exit",
        "-yy",
        "-s",
        "4096",
        "-o",
        str(trace),
        "-P",
        str(document),
        "-P",
        "VALIDATION.md",
        "-e",
        "trace=openat,close",
        "-e",
        "inject=openat:delay_enter=2s:when=3",
    ]
    if case == "deadline":
        arguments.extend(("-e", "inject=close:signal=SIGSTOP:when=2"))
    process = subprocess.Popen(
        [*arguments, *source_python("-I", "-c", program, str(SOURCE / "tools"), str(root), "8")],
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    tracee: int | None = None
    try:

        def document_closed() -> bool:
            """Record the tracee once it closes its first read of the document."""
            nonlocal tracee
            lines = trace.read_text().splitlines() if trace.exists() else []
            closes = [line for line in lines if "close(" in line and str(document) in line]
            if not closes:
                assert process.poll() is None, lines
                return False
            tracee = int(closes[0].split()[0])
            return True

        poll_until(
            document_closed,
            "Actual original VALIDATION.md first native read was not observed.",
            seconds=12,
        )
        assert tracee is not None
        if case == "source-bytes":
            document.write_bytes(original + b"\nActual received input changed.\n")
        elif case == "cache-kind":
            cache.rename(held)
            cache.symlink_to(held, target_is_directory=True)
        else:

            def producer_stopped() -> bool:
                """Report the kernel's SIGSTOP of the producer after its second close."""
                lines = trace.read_text().splitlines()
                stopped = any("SIGSTOP" in line and "SI_KERNEL" in line for line in lines)
                assert stopped or process.poll() is None, lines
                return stopped

            poll_until(
                producer_stopped,
                "Actual post-producer second-close SIGSTOP was not observed.",
                seconds=12,
            )
            time.sleep(9)
            os.kill(tracee, signal.SIGCONT)
        stdout, stderr = process.communicate(timeout=20)
        expected = 3 if case == "deadline" else 2
        assert process.returncode == expected, (stdout, stderr)
        notice = b'%s: Requested path "VALIDATION.md" resolved into "%s"\n' % (
            bytes(actual_strace),
            os.path.realpath(SOURCE / "VALIDATION.md").encode(),
        )
        assert stderr in (b"", notice), stderr
        assert json.loads(stdout) == {
            "code": {
                "source-bytes": "source_identity_mismatch",
                "cache-kind": "policy_refusal",
                "deadline": "tool_timeout",
            }[case],
            "exit_code": expected,
        }
        lines = trace.read_text().splitlines()
        opens = [line for line in lines if "openat(" in line and str(document) in line]
        assert len(opens) == 2 and all("O_RDONLY" in line for line in opens), lines
        assert "DELAYED" in opens[1], opens
        if case == "deadline":
            assert any("SIGSTOP" in line and "SI_KERNEL" in line for line in lines)
            assert any("SIGCONT" in line for line in lines)
    finally:
        stop(process, resume=tracee)
        document.write_bytes(original)
        if held.exists():
            cache.unlink()
            held.rename(cache)
    assert document.read_bytes() == original
    assert cache.is_dir() and not cache.is_symlink() and not held.exists()


def test_real_undecodable_owned_provenance_is_refused(root: Path) -> None:
    """Actual invalid UTF-8 source remains safely refused by the public byte consumer."""
    path = root / "tools/received.py"
    path.write_bytes(b"\xffActual invalid received source")
    before = snapshots(root)
    report = payload(run_guard("source_provenance", root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "input_encoding_invalid"
        for reason in reasons
    )
    assert snapshots(root) == before


def test_repository_reuse_report_keeps_half_the_capture_bound_free() -> None:
    """The repository's native REUSE report stays below half of the capture bound.

    The report grows with every tracked file. Failing at half the bound shows that growth
    while the source-provenance gate, which keeps the report, still passes.
    """
    report = analyse_reuse(SOURCE)
    assert report.exit_code == 0
    assert len(report.stdout) < MAX_CAPTURE // 2, (
        f"REUSE report of {len(report.stdout)} bytes has reached half of MAX_CAPTURE "
        f"({MAX_CAPTURE} bytes in tools/local_scaffold/limits.py)"
    )
