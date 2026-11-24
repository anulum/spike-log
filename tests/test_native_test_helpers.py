# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance
"""Exercise the shared helpers that stop, await and require native test children."""

import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import close_descriptor, poll_until, require_native, restore, stop

SLEEPER = [sys.executable, "-c", "import time; time.sleep(60)"]
"""A control child that runs until it is killed."""


def process_state(pid: int) -> str:
    """Return a live process's one-letter kernel state from /proc."""
    return (Path("/proc") / str(pid) / "stat").read_text().rsplit(") ", 1)[1].split()[0]


def test_stop_only_reaps_a_child_that_already_exited() -> None:
    """A child that has exited is reaped without a signal."""
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait(timeout=30)
    stop(child)
    assert child.returncode == 0


def test_stop_kills_a_running_child() -> None:
    """A running child is killed and reaped."""
    child = subprocess.Popen(SLEEPER)
    stop(child)
    assert child.returncode == -signal.SIGKILL


def test_stop_kills_the_whole_process_group() -> None:
    """A child in its own session is killed together with the processes of its group."""
    program = (
        "import subprocess, sys;"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']);"
        "print('started', flush=True);"
        "import time; time.sleep(60)"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", program], stdout=subprocess.PIPE, start_new_session=True
    )
    assert child.stdout is not None
    assert child.stdout.readline() == b"started\n"
    stop(child, group=True, timeout=None)
    assert child.returncode == -signal.SIGKILL
    # The grandchild holds the pipe too, so its end proves the whole group was killed.
    assert child.communicate(timeout=10)[0] == b""


def test_stop_continues_a_stopped_tracee_before_the_kill() -> None:
    """A stopped process named for resumption is continued before its controller is killed."""
    tracee = subprocess.Popen(SLEEPER)
    try:
        os.kill(tracee.pid, signal.SIGSTOP)
        poll_until(lambda: process_state(tracee.pid) == "T", "The tracee did not stop.", seconds=10)
        controller = subprocess.Popen(SLEEPER)
        stop(controller, resume=tracee.pid)
        assert controller.returncode == -signal.SIGKILL
        poll_until(
            lambda: process_state(tracee.pid) != "T", "The tracee was not continued.", seconds=10
        )
    finally:
        stop(tracee, resume=tracee.pid)


def test_stop_ignores_a_tracee_that_has_already_ended() -> None:
    """A process named for resumption that has already ended does not prevent the kill."""
    ended = subprocess.Popen([sys.executable, "-c", "pass"])
    ended.wait(timeout=30)
    controller = subprocess.Popen(SLEEPER)
    stop(controller, resume=ended.pid)
    assert controller.returncode == -signal.SIGKILL


def test_restore_leaves_the_original_when_nothing_is_held(tmp_path: Path) -> None:
    """Without a held original the current file stays as it is."""
    original = tmp_path / "original"
    original.write_bytes(b"current")
    restore(tmp_path / "held", original)
    assert original.read_bytes() == b"current"


def test_restore_moves_a_held_original_back(tmp_path: Path) -> None:
    """A held original returns to its own path."""
    held = tmp_path / "held"
    held.write_bytes(b"original")
    original = tmp_path / "original"
    restore(held, original)
    assert original.read_bytes() == b"original" and not held.exists()


def test_restore_replaces_what_took_the_original_place(tmp_path: Path) -> None:
    """A link the test put in the original's place is removed before the original returns."""
    held = tmp_path / "held"
    held.mkdir()
    (held / "kept").write_bytes(b"kept")
    original = tmp_path / "original"
    original.symlink_to(held, target_is_directory=True)
    restore(held, original, replace=True)
    assert not original.is_symlink() and (original / "kept").read_bytes() == b"kept"
    assert not held.exists()


def test_close_descriptor_closes_a_pipe_end_still_held() -> None:
    """A held pipe end is closed, so the reader sees end of file."""
    reader, writer = os.pipe()
    try:
        close_descriptor(writer)
        assert os.read(reader, 1) == b""
    finally:
        os.close(reader)


def test_close_descriptor_skips_a_pipe_end_already_cleared() -> None:
    """A descriptor the test already closed and cleared is left alone."""
    close_descriptor(None)


def test_poll_until_returns_once_the_step_completes() -> None:
    """The step is repeated until it reports completion."""
    calls: list[int] = []

    def third_call() -> bool:
        """Complete on the third observation."""
        calls.append(len(calls))
        return len(calls) == 3

    poll_until(third_call, "The step never completed.", seconds=10)
    assert calls == [0, 1, 2]


def test_poll_until_fails_with_its_message_at_the_deadline() -> None:
    """A step that never completes fails with the stated message."""
    with pytest.raises(AssertionError, match="^The awaited native event was not observed[.]$"):
        poll_until(lambda: False, "The awaited native event was not observed.", seconds=0.05)


def test_require_native_returns_a_present_fixture(tmp_path: Path) -> None:
    """A present fixture is returned unchanged."""
    fixture = tmp_path / "native-tool"
    fixture.write_bytes(b"")
    assert require_native(fixture, "The fixture is unavailable.") == fixture


def test_require_native_ends_the_run_for_an_absent_fixture(tmp_path: Path) -> None:
    """An absent fixture ends the whole run with exit 3 and the stated reason."""
    with pytest.raises(pytest.exit.Exception) as ended:
        require_native(tmp_path / "absent-tool", "Required native fixture is unavailable.")
    assert ended.value.returncode == 3
    assert ended.value.msg == "Required native fixture is unavailable."
