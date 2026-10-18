# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — synchronous process calling-context contract

"""Exercise real process API callers and complete finite plan integration."""

import asyncio
import gc
import sys
import warnings
from pathlib import Path

import pytest

from local_scaffold.orchestration import Role, run_plan, verify
from local_scaffold.policy import ROLES
from local_scaffold.processes import ProcessObservation, ProcessResult, run_process
from local_scaffold.reports import Fault, Report, validate_child


@pytest.mark.parametrize("runner", [False, True])
@pytest.mark.parametrize("supplied", [False, True])
def test_active_loop_refusal_and_observation_reuse(
    tmp_path: Path, runner: bool, supplied: bool
) -> None:
    """Refuse unsupported callers without warnings, child entry or evidence changes."""
    marker = tmp_path / "native-entry"
    command = [
        sys.executable,
        "-I",
        "-c",
        "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('entered');"
        "sys.stdout.write('out');sys.stderr.write('err');sys.exit(7)",
        str(marker),
    ]
    observation = ProcessObservation() if supplied else None

    async def call() -> None:
        """Call the public synchronous API from the actual running caller loop."""
        loop = asyncio.get_running_loop()
        with pytest.raises(Fault) as error:
            run_process(command, tmp_path, observation=observation)
        assert (error.value.code, error.value.exit_code) == ("configuration_invalid", 4)
        assert not marker.exists()
        await asyncio.sleep(0)
        assert asyncio.get_running_loop() is loop

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        if runner:
            with asyncio.Runner() as caller:
                caller.run(call())
        else:
            asyncio.run(call())
        gc.collect()
    assert not caught
    if observation is not None:
        assert not observation.stdout and not observation.stderr
        assert observation.native_exit is None and observation.native_completed_at is None
    result = run_process(command, tmp_path, observation=observation)
    assert (result.exit_code, result.stdout, result.stderr) == (7, b"out", b"err")
    assert marker.read_text() == "entered"
    if observation is not None:
        assert observation.native_exit == 7
        assert (bytes(observation.stdout), bytes(observation.stderr)) == (b"out", b"err")
        assert observation.native_completed_at is not None
        assert observation.native_completed_at.utcoffset() is not None


def test_worker_without_loop_while_caller_loop_runs(tmp_path: Path) -> None:
    """A different thread's active loop does not prevent real synchronous execution."""

    async def call() -> ProcessResult:
        """Run the synchronous public API on an actual worker without a running loop."""
        loop = asyncio.get_running_loop()
        result = await asyncio.to_thread(
            run_process,
            [sys.executable, "-I", "-c", "print('worker-output')"],
            tmp_path,
        )
        assert asyncio.get_running_loop() is loop
        return result

    result = asyncio.run(call())
    assert (result.exit_code, result.stdout, result.stderr) == (0, b"worker-output\n", b"")


def test_complete_finite_plan_retains_active_loop_invalidity(tmp_path: Path) -> None:
    """Record all eighteen invalid outcomes without inventing native tool execution."""
    marker = tmp_path / "unexpected-plan-child"
    command = (
        sys.executable,
        "-I",
        "-c",
        "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('entered')",
        str(marker),
    )
    roles = tuple(Role(name, command) for name in ROLES)
    report = Report("preflight")

    async def call() -> None:
        """Exercise the complete public finite-plan consumer in an actual active loop."""
        loop = asyncio.get_running_loop()
        run_plan(tmp_path, report, roles)
        await asyncio.sleep(0)
        assert asyncio.get_running_loop() is loop

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        asyncio.run(call())
        gc.collect()
    assert not caught and not marker.exists()
    assert report.exit_code == 4
    assert [check["role"] for check in report.checks] == list(ROLES)
    assert len(report.checks) == 18
    assert all(
        check["status"] == "invalid"
        and check["exit_code"] == 4
        and check["reason_codes"] == ["configuration_invalid"]
        for check in report.checks
    )
    validate_child(report.payload(), "preflight", 4)


def test_native_failure_preserves_later_finite_plan_execution(tmp_path: Path) -> None:
    """Keep an ordinary native failure while executing every later authorised role.

    Parameters
    ----------
    tmp_path : Path
        Owned directory holding an actual execution marker for each finite child.
    """
    program = (
        "import pathlib,sys;"
        "pathlib.Path(sys.argv[1]).write_text('entered');sys.exit(int(sys.argv[2]))"
    )
    roles = tuple(
        Role(
            name,
            (
                sys.executable,
                "-I",
                "-c",
                program,
                str(tmp_path / name),
                "7" if index == 0 else "0",
            ),
        )
        for index, name in enumerate(ROLES)
    )
    report = Report("preflight")
    run_plan(tmp_path, report, roles)
    assert report.exit_code == 2
    assert report.checks[0] == {
        "role": ROLES[0],
        "status": "refused",
        "exit_code": 2,
        "reason_codes": ["tool_failed"],
    }
    assert len(report.checks) == len(ROLES)
    assert all(
        outcome["status"] == "passed"
        and outcome["exit_code"] == 0
        and outcome["reason_codes"] == []
        for outcome in report.checks[1:]
    )
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(ROLES)
    assert all((tmp_path / name).read_text() == "entered" for name in ROLES)
    validate_child(report.payload(), "preflight", 2)


def test_missing_root_refuses_before_configured_role_execution(tmp_path: Path) -> None:
    """Reject an unavailable configured root without starting or recording a role.

    Parameters
    ----------
    tmp_path : Path
        Existing owned directory whose missing child is an ordinary invalid input.
    """
    root = tmp_path / "absent-repository"
    report = Report("preflight")
    with pytest.raises(Fault) as error:
        verify(root, report)
    assert (error.value.code, error.value.exit_code) == ("root_unavailable", 3)
    assert report.checks == []
    assert not root.exists() and list(tmp_path.iterdir()) == []
