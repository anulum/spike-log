# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Independent finite repository fixtures and actual public-command invocation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import cast

import pytest
from coverage import Coverage

from local_scaffold.inputs import Json

SOURCE = Path(__file__).resolve().parents[1]


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Retain actual per-case timings even when the complete native leaf times out."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "controller")
    directory = SOURCE / ".tool-cache/test-event-times"
    assert not directory.is_symlink()
    directory.mkdir(exist_ok=True)
    path = directory / (worker + "-" + str(os.getpid()) + ".jsonl")
    assert not path.is_symlink()
    value = {
        "nodeid": report.nodeid,
        "phase": report.when,
        "duration_seconds": report.duration,
        "outcome": report.outcome,
        "worker": worker,
        "native_pid": os.getpid(),
    }
    with path.open("a") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def source_python(*arguments: str, executable: str | None = None) -> list[str]:
    """Trace every owned Python child; retain raw unrelated control processes."""
    python = executable or sys.executable
    if Coverage.current() is None:
        # Only an unmeasured run of the tests takes this branch: under the measured suite coverage
        # is always active here, so no measured test can reach it.
        return [python, *arguments]  # pragma: no cover
    flags: list[str] = []
    remaining = list(arguments)
    while remaining[0] in ("-I", "-S", "-B"):
        flags.append(remaining.pop(0))
    if remaining[0] == "-c":
        program = remaining[1].encode()
        directory = SOURCE / ".tool-cache/test-source-programs"
        directory.mkdir(exist_ok=True)
        script = directory / (hashlib.sha256(program).hexdigest() + ".py")
        try:
            with script.open("xb") as stream:
                stream.write(program)
        except FileExistsError:
            assert script.read_bytes() == program
        remaining = [str(script), *remaining[2:]]
    launcher = """import os,pathlib,runpy,sys
from coverage import Coverage,CoverageData
configuration=sys.argv[1]
arguments=sys.argv[2:]
root=pathlib.Path(configuration).parent
settings=Coverage(config_file=configuration)
names=settings.get_option('run:source')
data_file=os.environ.get('COVERAGE_FILE') or str(root/settings.get_option('run:data_file'))
copies={pathlib.Path.cwd().resolve()}
if arguments[0]!='-m':
    script=pathlib.Path(arguments[0]).resolve()
    copies.update(p for p in script.parents if (p/'pyproject.toml').is_file())
copies=[copy for copy in copies if not root.is_relative_to(copy)]
copies.sort(key=lambda copy:len(copy.parts),reverse=True)
source=[str(base/name) for base in (root,*copies) for name in names if (base/name).is_dir()]
class Measured(Coverage):
    def save(self):
        measured=self.get_data()
        merged=CoverageData(basename=data_file,suffix=True)
        for name in measured.measured_files():
            path=pathlib.Path(name)
            copy=next((copy for copy in copies if path.is_relative_to(copy)),None)
            target=path if copy is None else root/path.relative_to(copy)
            if copy is not None:
                try:
                    same=target.read_bytes()==path.read_bytes()
                except OSError:
                    same=False
                if not same:
                    continue
            if measured.has_arcs():
                merged.add_arcs({str(target):measured.arcs(name) or []})
            else:
                merged.add_lines({str(target):measured.lines(name) or []})
        merged.write()
coverage=Measured(config_file=configuration,data_file=None,source=source)
coverage.set_option('run:data_file',data_file)
coverage.set_option('run:disable_warnings',['no-data-collected'])
coverage.start()
try:
    if arguments[0]=='-m':
        sys.argv=[arguments[1],*arguments[2:]]
        runpy.run_module(arguments[1],run_name='__main__',alter_sys=True)
    else:
        script=pathlib.Path(arguments[0]).resolve()
        sys.path.insert(0,str(script.parent))
        sys.argv=[str(script),*arguments[1:]]
        runpy.run_path(script,run_name='__main__')
finally:
    coverage.stop()
    coverage.save()
"""
    return [python, *flags, "-c", launcher, str(SOURCE / "pyproject.toml"), *remaining]


def stop(
    process: subprocess.Popen[bytes],
    *,
    group: bool = False,
    timeout: float | None = 5,
    resume: int | None = None,
) -> None:
    """Kill a native child that is still running, then reap it.

    Parameters
    ----------
    process : subprocess.Popen[bytes]
        Child the test started; one that already exited is only reaped.
    group : bool
        Kill the child's whole process group, for a child started in its own session.
    timeout : float | None
        Seconds to wait for the reaped exit, or None to wait without a bound.
    resume : int | None
        A stopped traced process to continue first, so the kill is not held by its stop.
    """
    if process.poll() is None:
        if resume is not None:
            with suppress(ProcessLookupError):
                os.kill(resume, signal.SIGCONT)
        if group:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    process.wait(timeout=timeout)


def restore(held: Path, original: Path, *, replace: bool = False) -> None:
    """Move a held original back after an interrupted test.

    Parameters
    ----------
    held : Path
        Where the test moved the original; nothing happens when it is absent.
    original : Path
        The original's own path.
    replace : bool
        Remove what the test put in the original's place first.
    """
    if held.exists():
        if replace:
            original.unlink()
        held.rename(original)


def close_descriptor(descriptor: int | None) -> None:
    """Close a pipe end the test still holds; one it already closed and cleared is skipped.

    Parameters
    ----------
    descriptor : int | None
        The open descriptor, or None once the test has closed it itself.
    """
    if descriptor is not None:
        os.close(descriptor)


def poll_until(
    step: Callable[[], bool], message: str, *, seconds: float, interval: float = 0.001
) -> None:
    """Repeat a step until it reports completion, failing after a native deadline.

    Parameters
    ----------
    step : Callable[[], bool]
        Observes the native event and acts on it, returning True once it has.
    message : str
        Failure stated when the event is not observed in time.
    seconds : float
        Deadline, measured on the monotonic clock.
    interval : float
        Pause between observations.

    Raises
    ------
    AssertionError
        Raised with ``message`` when the step has not completed by the deadline.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if step():
            return
        time.sleep(interval)
    raise AssertionError(message)


def require_native(path: Path, message: str) -> Path:
    """Return a required native fixture; its absence ends the run and never simulates success.

    Parameters
    ----------
    path : Path
        The fixture's executable or file.
    message : str
        Reason stated when the whole run ends with exit 3.

    Returns
    -------
    Path
        ``path`` itself, present as a regular file.
    """
    if not path.is_file():
        pytest.exit(message, returncode=3)
    return path


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """Copy actual owned inputs and initialise a genuine isolated local Git tree."""
    target = tmp_path / "repository"
    shutil.copytree(
        SOURCE,
        target,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".tool-cache",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        ),
    )
    cache = target / ".tool-cache/security"
    cache.mkdir(parents=True)
    shutil.copyfile(SOURCE / ".tool-cache/security/pip-audit.json", cache / "pip-audit.json")
    subprocess.run(["git", "init", "--quiet", "-b", "main", str(target)], check=True)
    return target


def run_guard(gate: str, root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    """Invoke the actual fixed public script with real native process semantics."""
    filename = "preflight.py" if gate == "preflight" else "check_" + gate + ".py"
    return subprocess.run(
        source_python(
            str(SOURCE / "tools" / filename),
            "--root",
            str(root),
            "--json",
            *arguments,
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=120,
    )


def payload(result: subprocess.CompletedProcess[bytes], expected: int) -> dict[str, Json]:
    """Assert complete native/report agreement and safe deterministic wire shape."""
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert not result.stderr, result.stderr
    value = cast(dict[str, Json], json.loads(result.stdout))
    assert set(value) == {
        "report_schema",
        "gate",
        "scope",
        "status",
        "exit_code",
        "reasons",
        "checks",
    }
    assert value["exit_code"] == expected
    assert value["status"] == {0: "passed", 2: "refused", 3: "unavailable", 4: "invalid"}[expected]
    assert value["report_schema"] == "spike_log.local-scaffold-guard-report.v1"
    assert result.stdout.endswith(b"\n")
    assert len(result.stdout) <= 524288
    return value


def change(root: Path, name: str, path: tuple[str, ...], replacement: Json) -> None:
    """Change one independently chosen actual JSON input, preserving valid encoding."""
    filename = root / name
    value = cast(dict[str, Json], json.loads(filename.read_bytes()))
    current = value
    for key in path[:-1]:
        child = current[key]
        assert isinstance(child, dict)
        current = child
    current[path[-1]] = replacement
    filename.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n")


def snapshots(root: Path) -> dict[str, bytes]:
    """Retain every original owned file's actual bytes for read-only assertions."""
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
        and not any(
            part in (".git", ".tool-cache", "__pycache__") for part in path.relative_to(root).parts
        )
    }


def closed_stdout(gate: str, root: Path) -> int:
    """Close an actual pipe consumer before the real guard attempts report output."""
    filename = "preflight.py" if gate == "preflight" else "check_" + gate + ".py"
    reader, writer = os.pipe()
    os.close(reader)
    try:
        result = subprocess.run(
            source_python(
                str(SOURCE / "tools" / filename),
                "--root",
                str(root),
                "--json",
                "--unknown-private-sentinel",
            ),
            cwd=SOURCE,
            stdout=writer,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    finally:
        os.close(writer)
    assert b"private-sentinel" not in result.stderr
    return result.returncode


@pytest.fixture
def audited_clone(root: Path) -> Path:
    """Copy genuine original local admission objects into a distinct owned installation."""
    wheels = root / ".tool-cache/environment-inputs"
    wheels.mkdir()
    for name in (
        "evidence_manifest_toolkit-0.0.0.dev0-py3-none-any.whl",
        "rfc8785-0.1.4+emt.1-py3-none-any.whl",
    ):
        os.link(SOURCE / ".tool-cache/environment-inputs" / name, wheels / name)
    source = SOURCE / ".tool-cache/security-admissions"
    target = root / ".tool-cache/security-admissions"
    target.mkdir()
    shutil.copytree(source / "objects", target / "objects")
    shutil.copyfile(source / "HEAD.json", target / "HEAD.json")
    shutil.copyfile(source / "admission.lock", target / "admission.lock")
    return root


def clone_dependency(root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    """Exercise the cloned real implementation so its actual installation owns its store."""
    return subprocess.run(
        source_python(
            str(root / "tools/check_dependency_alignment.py"),
            "--root",
            str(root),
            "--json",
            *arguments,
        ),
        cwd=root,
        capture_output=True,
        timeout=120,
    )


def adverse_audit_receipt(root: Path, changes: dict[str, Json]) -> None:
    """Publish only an explicitly adverse owned fixture, never a synthetic passing receipt."""
    store = root / ".tool-cache/security-admissions"
    head = cast(dict[str, Json], json.loads((store / "HEAD.json").read_bytes()))
    selector = head["receipt_sha256"]
    assert isinstance(selector, str)
    receipt = cast(
        dict[str, Json], json.loads((store / "objects" / (selector + ".json")).read_bytes())
    )
    assert changes and any(
        type(receipt.get(key)) is not type(value) or receipt.get(key) != value
        for key, value in changes.items()
    )
    receipt["installation_sha256"] = hashlib.sha256(
        b"spike_log.trusted-installation.v1\0" + str(root.resolve()).encode()
    ).hexdigest()
    receipt.update(changes)
    data = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    new_selector = hashlib.sha256(data).hexdigest()
    (store / "objects" / (new_selector + ".json")).write_bytes(data)
    head["receipt_sha256"] = new_selector
    (store / "HEAD.json").write_text(json.dumps(head) + "\n")
