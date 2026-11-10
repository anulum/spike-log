# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise genuine child processes and the public finite orchestration boundary."""

import ctypes
import json
import math
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from local_scaffold.orchestration import Role, run_plan
from local_scaffold.processes import ProcessObservation, execute, run_process
from local_scaffold.reports import Fault, Report, validate_child
from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python
from tests.test_atomic_publication import actual_strace as actual_strace

ROLES = (
    "repository_metadata",
    "source_provenance",
    "workflow_policy",
    "dependency_alignment",
    "documentation",
    "repository_inventory",
    "python_lint",
    "python_format",
    "python_strict_typing",
    "python_native_documentation",
    "python_security",
    "infrastructure_tests_coverage",
    "reuse_licence",
    "secret_scan",
    "dependency_security",
    "actionlint",
    "workflow_security",
    "sbom",
)


def plan(program: str, gate: str | None = None) -> tuple[Role, ...]:
    """Authorise explicit finite children solely to qualify orchestration behaviour."""
    return tuple(Role(name, (sys.executable, "-c", program), gate) for name in ROLES)


def test_public_plan_and_native_captures(root: Path) -> None:
    """Actual native exits and pipe captures are retained without tool qualification."""
    result = run_process(
        [
            sys.executable,
            "-c",
            "import sys;sys.stdout.write('out');sys.stderr.write('err');sys.exit(7)",
        ],
        root,
    )
    assert (result.exit_code, result.stdout, result.stderr) == (7, b"out", b"err")
    report = Report("preflight")
    run_plan(root, report, plan("pass"))
    assert report.exit_code == 0
    assert len(report.checks) == 18
    validate_child(report.payload(), "preflight", 0)


def test_actual_authorised_child_environment(root: Path) -> None:
    """An explicit owned child environment preserves the parent's original values."""
    before = dict(os.environ)
    result = run_process(
        [
            sys.executable,
            "-I",
            "-c",
            "import os;print(os.environ['SPIKE_LOG_OWNED_PROCESS_VALUE'])",
        ],
        root,
        environment={**os.environ, "SPIKE_LOG_OWNED_PROCESS_VALUE": "explicit-authorised-child"},
    )
    assert (result.exit_code, result.stdout, result.stderr) == (
        0,
        b"explicit-authorised-child\n",
        b"",
    )
    assert dict(os.environ) == before


@pytest.mark.parametrize("blocked", [set(), {signal.SIGUSR1, signal.SIGTERM}])
def test_actual_child_and_caller_signal_masks(root: Path, blocked: set[signal.Signals]) -> None:
    """Real child execution and return preserve the caller's signal delivery policy."""
    original = signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
    try:
        result = run_process(
            [
                sys.executable,
                "-I",
                "-c",
                "import json,signal;print(json.dumps(sorted(signal.pthread_sigmask("
                "signal.SIG_BLOCK,set()))))",
            ],
            root,
        )
        assert result.exit_code == 0 and not result.stderr
        assert json.loads(result.stdout) == sorted(blocked)
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == blocked
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, original)


def test_original_async_execution_call_remains_compatible(root: Path) -> None:
    """The original five-argument async call retains real exit, capture and cleanup."""
    import asyncio

    observation = ProcessObservation()
    result = asyncio.run(
        execute(
            [sys.executable, "-I", "-c", "import sys;print('owned-output');sys.exit(7)"],
            root,
            time.monotonic() + 2,
            0.2,
            observation,
        )
    )
    assert (result.exit_code, result.stdout, result.stderr) == (7, b"owned-output\n", b"")
    assert observation.native_exit == 7


@pytest.mark.parametrize(
    "program",
    [
        "print('not-json')",
        "print('{}')",
        "import sys;sys.exit(2)",
        "import sys;sys.stdout.write('x'*262145)",
    ],
)
def test_real_child_refusals(root: Path, program: str) -> None:
    """Malformed transports, real failures and real output overflow refuse."""
    report = Report("preflight")
    run_plan(root, report, plan(program, "repository_metadata"))
    assert report.exit_code == 2
    assert len(report.checks) == 18


def test_native_report_conflict_and_precedence(root: Path) -> None:
    """Real children emit contradictory native exits or genuine authored faults."""
    record = {
        "report_schema": "spike_log.local-scaffold-guard-report.v1",
        "gate": "repository_metadata",
        "scope": "local_scaffold",
        "status": "passed",
        "exit_code": 0,
        "reasons": [],
        "checks": [],
    }
    report = Report("preflight")
    run_plan(
        root,
        report,
        plan(
            "import json,sys;print(" + repr(json.dumps(record)) + ");sys.exit(2)",
            "repository_metadata",
        ),
    )
    assert report.exit_code == 2
    children = []
    for i, name in enumerate(ROLES):
        code = (2, 3, 4)[i % 3]
        reason = ("policy_refusal", "tool_unavailable", "configuration_invalid")[i % 3]
        value = {
            **record,
            "exit_code": code,
            "status": {2: "refused", 3: "unavailable", 4: "invalid"}[code],
            "reasons": [
                {
                    "code": reason,
                    "location": None,
                    "detail": "Required local infrastructure condition failed: " + reason + ".",
                }
            ],
        }
        children.append(
            Role(
                name,
                (
                    sys.executable,
                    "-c",
                    "import sys;print(" + repr(json.dumps(value)) + ");sys.exit(" + str(code) + ")",
                ),
                "repository_metadata",
            )
        )
    report = Report("preflight")
    run_plan(root, report, tuple(children))
    assert report.exit_code == 4
    assert {check["exit_code"] for check in report.checks} == {2, 3, 4}


@pytest.mark.parametrize("case", ["empty", "budget", "cycle"])
def test_plan_configuration(root: Path, case: str) -> None:
    """Missing roles, excessive budget and recursive child commands are invalid."""
    roles = () if case == "empty" else plan("pass")
    if case == "cycle":
        roles = tuple(Role(name, (sys.executable, "preflight.py")) for name in ROLES)
    with pytest.raises(Fault) as error:
        run_plan(root, Report("preflight"), roles, 601 if case == "budget" else 600)
    assert error.value.exit_code == 4


def test_shared_budget_and_missing_program(root: Path) -> None:
    """Actual missing executables and budget exhaustion never become passes."""
    with pytest.raises(Fault) as missing:
        run_process([str(root / "nonexistent-program")], root)
    assert missing.value.exit_code == 3
    report = Report("preflight")
    run_plan(root, report, plan("import time;time.sleep(1)"), 0.2)
    assert report.exit_code == 3
    assert any(check["status"] == "not_run" for check in report.checks)


@pytest.mark.parametrize("duration", [0.0, -1.0, 121.0, math.nan, math.inf, True])
def test_leaf_budget_is_finite_configuration(root: Path, duration: float) -> None:
    """A trusted caller cannot authorise a nonfinite, Boolean or excessive leaf budget."""
    with pytest.raises(Fault) as error:
        run_process([sys.executable, "-c", "pass"], root, duration)
    assert error.value.code == "configuration_invalid" and error.value.exit_code == 4


@pytest.mark.parametrize("duration", [0.0, -1.0, 601.0, math.nan, math.inf, True])
def test_shared_budget_is_finite_configuration(root: Path, duration: float) -> None:
    """Invalid shared budgets refuse before any of the18 authorised children starts."""
    report = Report("preflight")
    with pytest.raises(Fault) as error:
        run_plan(root, report, plan("pass"), duration)
    assert error.value.code == "configuration_invalid" and error.value.exit_code == 4
    assert not report.checks


def test_group_reaping_preserves_unrelated_process(root: Path) -> None:
    """Real timed-out grandchildren are reaped while an unrelated sentinel lives."""
    sentinel = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(30)"], start_new_session=True
    )
    pidfile = root / "grandchild.pid"
    code = "import subprocess,sys,time,pathlib;child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);pathlib.Path(sys.argv[1]).write_text(str(child.pid));time.sleep(30)"
    try:
        with pytest.raises(Fault) as error:
            run_process([sys.executable, "-I", "-c", code, str(pidfile)], root, 2)
        assert error.value.exit_code == 3
        assert sentinel.poll() is None
        assert not Path("/proc/" + pidfile.read_text()).exists()
    finally:
        sentinel.terminate()
        sentinel.wait(timeout=5)


@pytest.fixture
def owned_subreaper(tmp_path: Path) -> Iterator[Path]:
    """Reap only explicitly recorded actors after real failed cleanup syscalls."""
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    directory = tmp_path / "owned-native-processes"
    directory.mkdir()
    try:
        yield directory
    finally:
        try:
            for pidfile in directory.glob("*.pid"):
                pid = int(pidfile.read_text())
                assert pid > 1 and pid != os.getpid()
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    assert not Path("/proc/" + str(pid)).exists()
                    continue
                if waited == 0:
                    os.kill(pid, signal.SIGKILL)
                    waited, _ = os.waitpid(pid, 0)
                assert waited == pid
        finally:
            assert libc.prctl(36, previous.value, 0, 0, 0) == 0


@pytest.mark.parametrize("recover", [True, False])
def test_actual_successful_leader_late_group_reaping(
    root: Path, tmp_path: Path, owned_subreaper: Path, actual_strace: Path, recover: bool
) -> None:
    """A native0 leader's surviving group reaps late or refuses at the real deadline."""
    ready = owned_subreaper / "grandchild.pid"
    actor = """import os,pathlib,signal,sys,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(30)
"""
    leader = """import pathlib,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-I','-c',sys.argv[2],sys.argv[1]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
deadline=time.monotonic()+5
while not pathlib.Path(sys.argv[1]).exists():
    if child.poll() is not None or time.monotonic()>=deadline:
        raise RuntimeError('Owned grandchild did not initialise.')
    time.sleep(0.005)
"""
    program = """import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.processes import ProcessObservation,run_process
from local_scaffold.reports import Fault
observation=ProcessObservation()
try:
    result=run_process([sys.executable,'-I','-c',sys.argv[3],sys.argv[4],sys.argv[5]],Path(sys.argv[2]),10,observation=observation)
    print(json.dumps({'exit_code':result.exit_code,'native_exit':observation.native_exit}))
except Fault as fault:
    print(json.dumps({'code':fault.code,'exit_code':fault.exit_code,'native_exit':observation.native_exit}))
    sys.exit(fault.exit_code)
"""
    trace = tmp_path / "actual_late_group_reaping.native-trace"
    before = snapshots(root)
    started = time.monotonic()
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-o",
            str(trace),
            "-e",
            "trace=kill,wait4",
            "-e",
            "inject=wait4:retval=0:when=" + ("2..401" if recover else "2+"),
            *source_python(
                "-I", "-c", program, str(SOURCE / "tools"), str(root), leader, str(ready), actor
            ),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=20,
    )
    elapsed = time.monotonic() - started
    assert not result.stderr, result.stderr
    record = json.loads(result.stdout)
    assert record == (
        {"exit_code": 0, "native_exit": 0}
        if recover
        else {"code": "tool_timeout", "exit_code": 3, "native_exit": 0}
    ), (record, trace.read_text())
    assert result.returncode == (0 if recover else 3)
    assert elapsed < 15 and elapsed >= (4 if recover else 10)
    calls = trace.read_bytes().splitlines()
    injected = [line for line in calls if b"INJECTED" in line]
    assert len(injected) == 400 if recover else len(injected) > 400
    assert all(
        line.startswith(b"wait4(-") and b"= 0 (INJECTED)" in b" ".join(line.split())
        for line in injected
    )
    pid = int(ready.read_text())
    assert any(b"SIGTERM" in line for line in calls)
    assert any(b"SIGKILL" in line for line in calls)
    if recover:
        assert not Path("/proc/" + str(pid)).exists()
        assert any(b"= " + str(pid).encode() in line and b"SIGKILL" in line for line in calls)
    else:
        assert Path("/proc/" + str(pid)).exists()
    assert snapshots(root) == before


def test_actual_suppressed_kill_reaches_cleanup_timeout(
    root: Path, tmp_path: Path, owned_subreaper: Path, actual_strace: Path
) -> None:
    """Suppress every owned SIGKILL, including asyncio's native transport cleanup."""
    pidfile = owned_subreaper / "leader.pid"
    actor = """import os,pathlib,signal,sys,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(30)
"""
    program = """import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.processes import ProcessObservation,run_process
from local_scaffold.reports import Fault
observation=ProcessObservation()
try:
    run_process([sys.executable,'-I','-c',sys.argv[3],sys.argv[4]],Path(sys.argv[2]),3,observation=observation)
except Fault as fault:
    print(json.dumps({'code':fault.code,'exit_code':fault.exit_code,'native_exit':observation.native_exit}))
    sys.exit(fault.exit_code)
raise RuntimeError('Suppressed SIGKILL unexpectedly accepted.')
"""
    trace = tmp_path / "actual_suppressed_SIGKILL.native-trace"
    before = snapshots(root)
    started = time.monotonic()
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-o",
            str(trace),
            "-e",
            "trace=kill,wait4",
            "-e",
            "inject=kill:retval=0:when=2+",
            *source_python(
                "-I", "-c", program, str(SOURCE / "tools"), str(root), actor, str(pidfile)
            ),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 3 and not result.stderr, (result.stdout, result.stderr)
    assert json.loads(result.stdout) == {
        "code": "tool_timeout",
        "exit_code": 3,
        "native_exit": None,
    }
    assert 3 <= time.monotonic() - started < 8
    pid = int(pidfile.read_text())
    injected = [line for line in trace.read_bytes().splitlines() if b"INJECTED" in line]
    group_kill = b"kill(-" + str(pid).encode() + b", SIGKILL) = 0 (INJECTED)"
    leader_kill = b"kill(" + str(pid).encode() + b", SIGKILL) = 0 (INJECTED)"
    assert injected and b" ".join(injected[0].split()) == group_kill
    assert all(b" ".join(line.split()) in (group_kill, leader_kill) for line in injected)
    assert Path("/proc/" + str(pid)).exists()
    assert snapshots(root) == before


def test_preflight_invocation_boundary(root: Path) -> None:
    """Actual invalid profile preserves all not-run roles and safe native exit."""
    value = payload(run_guard("preflight", root, "--profile", "private-sentinel"), 4)
    validate_child(value, "preflight", 4)
    assert isinstance(value["checks"], list)
    assert len(value["checks"]) == 18


def test_authorised_working_directory(root: Path) -> None:
    """A caller-authorised finite process plan runs in its explicitly owned directory."""
    directory = root / "owned-child-directory"
    directory.mkdir()
    program = "import os,sys;sys.exit(0 if os.getcwd()==sys.argv[1] else 7)"
    roles = tuple(
        Role(name, (sys.executable, "-c", program, str(directory)), working_directory=directory)
        for name in ROLES
    )
    report = Report("preflight")
    run_plan(root, report, roles)
    assert report.exit_code == 0
    validate_child(report.payload(), "preflight", 0)


def test_real_interruption_retains_every_outcome(root: Path) -> None:
    """An owned child's actual SIGINT interrupts its parent and retains every later not_run."""
    program = "import os,signal,time;os.kill(os.getppid(),signal.SIGINT);time.sleep(30)"
    parent = (
        "import sys;sys.path.insert(0,sys.argv[1]);"
        "from pathlib import Path;from local_scaffold.orchestration import Role,run_plan;"
        "from local_scaffold.reports import Report;"
        "from local_scaffold.policy import ROLES;"
        "roles=tuple(Role(n,(sys.executable,'-c',sys.argv[3])) for n in ROLES);"
        "report=Report('preflight');run_plan(Path(sys.argv[2]),report,roles);"
        "sys.exit(report.emit(True))"
    )
    from tests.conftest import SOURCE, source_python

    result = subprocess.run(
        source_python("-c", parent, str(SOURCE / "tools"), str(root), program),
        capture_output=True,
        timeout=15,
        check=False,
    )
    record = payload(result, 3)
    checks = record["checks"]
    assert isinstance(checks, list)
    first = checks[0]
    assert isinstance(first, dict)
    assert first["reason_codes"] == ["interrupted"]
    assert all(isinstance(check, dict) and check.get("status") == "not_run" for check in checks[1:])
    validate_child(record, "preflight", 3)


def test_received_python_configuration_cannot_execute(root: Path) -> None:
    """Real tool invocations cannot import received Python modules or mypy plugins."""
    from local_scaffold.orchestration import configured_roles
    from tests.conftest import SOURCE, source_python

    marker = root / "received-program-ran"
    poison = (
        '"""Received executable fixture which must never run."""\nfrom pathlib import Path\nPath('
        + repr(str(marker))
        + ').write_text("ran")\n'
    )
    (root / "ruff.py").write_text(poison)
    (root / "received_plugin.py").write_text(poison)
    configuration = root / "pyproject.toml"
    configuration.write_text(
        configuration.read_text().replace(
            "strict = true", 'strict = true\nplugins = ["received_plugin.py"]'
        )
    )
    roles = {role.name: role for role in configured_roles(root)}
    for name in ("python_lint", "python_strict_typing"):
        role = roles[name]
        result = run_process(list(role.command), role.working_directory or root)
        assert result.exit_code == 0, result.stderr
    guard = roles["repository_metadata"]
    result = run_process(source_python(*guard.command[1:]), guard.working_directory or root)
    payload(
        subprocess.CompletedProcess(guard.command, result.exit_code, result.stdout, result.stderr),
        0,
    )
    assert not marker.exists()
    assert roles["infrastructure_tests_coverage"].working_directory == SOURCE


@pytest.mark.parametrize(
    "program",
    [
        "import os,time;os.close(1);os.close(2);time.sleep(30)",
        "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)",
    ],
)
def test_actual_pipe_closure_and_forced_termination(root: Path, program: str) -> None:
    """Closed pipes and ignored TERM preserve inclusive deadline and real reaping."""
    import time

    began = time.monotonic()
    with pytest.raises(Fault) as error:
        run_process([sys.executable, "-c", program], root, 0.4)
    assert error.value.code == "tool_timeout"
    assert time.monotonic() - began < 0.8


def test_plan_adopts_exact_bound_native_role(root: Path) -> None:
    """Actual native Actionlint qualifies its explicit role after all view checks."""
    from local_scaffold.orchestration import configured_roles

    fixed = next(role for role in configured_roles(root) if role.name == "actionlint")
    assert fixed.workflow_root == root
    roles = tuple(fixed if role.name == "actionlint" else role for role in plan("pass"))
    report = Report("preflight")
    run_plan(root, report, roles)
    validate_child(report.payload(), "preflight", 0)
    assert report.checks[ROLES.index("actionlint")] == {
        "role": "actionlint",
        "status": "passed",
        "exit_code": 0,
        "reason_codes": [],
    }
    assert not list((root / ".tool-cache").glob("actionlint-view-*"))


def test_semantic_view_cannot_change_another_role(root: Path) -> None:
    """A trusted plan cannot attach the workflow interpretation to a different role."""
    roles = tuple(
        Role(role.name, role.command, workflow_root=root if role.name == "sbom" else None)
        for role in plan("pass")
    )
    report = Report("preflight")
    with pytest.raises(Fault) as error:
        run_plan(root, report, roles)
    assert error.value.code == "configuration_invalid" and error.value.exit_code == 4
    assert not report.checks


def test_actual_failure_capture_stays_private(root: Path) -> None:
    """A genuine timeout retains exact private prefixes without placing them in Fault."""
    from local_scaffold.processes import ProcessObservation

    observation = ProcessObservation()
    program = "import os,time;os.write(1,b'private-output-sentinel');os.write(2,b'private-error-sentinel');time.sleep(30)"
    with pytest.raises(Fault) as error:
        run_process([sys.executable, "-I", "-c", program], root, 2, observation=observation)
    assert error.value.code == "tool_timeout" and error.value.exit_code == 3
    assert bytes(observation.stdout) == b"private-output-sentinel"
    assert bytes(observation.stderr) == b"private-error-sentinel"
    assert observation.native_exit in (-15, -9)
    report = Report("repository_metadata")
    report.observe(error.value)
    assert "private-" not in json.dumps(report.payload())
    assert "private-" not in str(error.value)


def test_success_capture_and_stale_container_refusal(root: Path) -> None:
    """Real native7 is retained exactly; reusing the same evidence container refuses."""
    from local_scaffold.processes import ProcessObservation

    observation = ProcessObservation()
    result = run_process(
        [
            sys.executable,
            "-I",
            "-c",
            "import os,sys;os.write(1,b'out');os.write(2,b'err');sys.exit(7)",
        ],
        root,
        observation=observation,
    )
    assert (result.exit_code, result.stdout, result.stderr) == (7, b"out", b"err")
    assert (observation.native_exit, bytes(observation.stdout), bytes(observation.stderr)) == (
        7,
        b"out",
        b"err",
    )
    with pytest.raises(Fault) as error:
        run_process([sys.executable, "-I", "-c", "pass"], root, observation=observation)
    assert error.value.code == "configuration_invalid" and error.value.exit_code == 4
    assert observation.native_exit == 7 and bytes(observation.stdout) == b"out"


def test_overflow_capture_is_actually_bounded(root: Path) -> None:
    """Actual pipe overflow refuses while the private prefix stays at the original cap."""
    from local_scaffold.processes import ProcessObservation

    observation = ProcessObservation()
    with pytest.raises(Fault) as error:
        run_process(
            [sys.executable, "-I", "-c", "import os;os.write(1,b'x'*262145)"],
            root,
            observation=observation,
        )
    assert error.value.code == "tool_output_limit" and error.value.exit_code == 2
    assert len(observation.stdout) <= 262144
    assert observation.stdout and set(observation.stdout) == {120}
    assert not observation.stderr


def test_missing_program_has_no_invented_exit(root: Path) -> None:
    """An actual absent exec target leaves no fabricated native exit or output."""
    from local_scaffold.processes import ProcessObservation

    observation = ProcessObservation()
    with pytest.raises(Fault) as error:
        run_process([str(root / "actual-absent-executable")], root, observation=observation)
    assert error.value.code == "tool_unavailable" and error.value.exit_code == 3
    assert observation.native_exit is None and not observation.stdout and not observation.stderr


@pytest.mark.parametrize("adverse", [False, True])
def test_original_native_licence_role_uses_complete_public_input(root: Path, adverse: bool) -> None:
    """The actual licence role retains real REUSE success and genuine native failure."""
    if adverse:
        (root / "REUSE.toml").write_text("version = 1\n")
        (root / "unlicensed.txt").write_text("Received unlicensed public input.\n")
    roles = list(plan("pass"))
    roles[ROLES.index("reuse_licence")] = Role("reuse_licence", (), licence_root=root)
    report = Report("preflight")
    run_plan(root, report, tuple(roles))
    assert len(report.checks) == 18
    observed = report.checks[ROLES.index("reuse_licence")]
    assert observed["role"] == "reuse_licence"
    assert observed["exit_code"] == (2 if adverse else 0)
    assert observed["reason_codes"] == (["tool_failed"] if adverse else [])
    validate_child(report.payload(), "preflight", 2 if adverse else 0)


def test_licence_input_cannot_change_another_role(root: Path) -> None:
    """The fixed licence representation cannot be attached to another plan role."""
    roles = list(plan("pass"))
    roles[0] = Role("repository_metadata", (), licence_root=root)
    report = Report("preflight")
    with pytest.raises(Fault) as error:
        run_plan(root, report, tuple(roles))
    assert error.value.code == "configuration_invalid" and error.value.exit_code == 4
    assert not report.checks


def test_public_preflight_real_descriptor_exhaustion_is_unavailable(root: Path) -> None:
    """Actual EMFILE during native producer resolution preserves all not-run roles."""
    program = """import resource,sys
sys.path.insert(0,sys.argv[1])
import local_scaffold.orchestration
from local_scaffold.cli import main
original=resource.getrlimit(resource.RLIMIT_NOFILE)
try:
    resource.setrlimit(resource.RLIMIT_NOFILE,(3,original[1]))
    code=main('preflight',['--root',sys.argv[2],'--json'])
finally:
    resource.setrlimit(resource.RLIMIT_NOFILE,original)
sys.exit(code)
"""
    before = snapshots(root)
    result = subprocess.run(
        source_python("-I", "-c", program, str(SOURCE / "tools"), str(root)),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    value = payload(result, 3)
    checks = value["checks"]
    assert isinstance(checks, list) and len(checks) == 18
    assert all(isinstance(check, dict) and check["status"] == "not_run" for check in checks)
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "input_unavailable" for reason in reasons
    )
    validate_child(value, "preflight", 3)
    assert snapshots(root) == before
