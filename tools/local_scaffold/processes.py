# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Run trusted exec-only commands with bounded capture and owned Linux groups."""

from __future__ import annotations

import asyncio
import ctypes
import math
import os
import signal
import threading
import time
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, Final, cast

from .policy import LEAF_SECONDS, MAX_CAPTURE
from .reports import Fault

INTERRUPTS: Final = (signal.SIGINT, signal.SIGTERM)
"""Signals that interrupt a process operation; its own loop receives them while it runs."""


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Actual native process exit and privately retained bounded raw captures.

    Attributes
    ----------
    exit_code : int
        Actual child native exit after owned cleanup.
    stdout : bytes
        Complete bounded original stdout bytes, retained privately.
    stderr : bytes
        Complete bounded original stderr bytes, retained privately.
    """

    exit_code: int
    stdout: bytes
    stderr: bytes


@dataclass(slots=True)
class ProcessObservation:
    """Privately retain bounded actual pipe prefixes and the native child exit.

    A caller owns this optional evidence container. Raw bytes never enter Fault
    or the public guard report. One invocation requires a fresh empty container.

    Attributes
    ----------
    stdout : bytearray
        Actual bounded stdout prefix collected into this fresh caller-owned buffer.
    stderr : bytearray
        Actual bounded stderr prefix collected into this fresh caller-owned buffer.
    native_exit : int | None
        Observed native child exit, or None before child termination is observed.
    native_completed_at : datetime | None
        Actual aware UTC observation of native child completion, before output validation.
    """

    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    native_exit: int | None = None
    native_completed_at: datetime | None = None


@dataclass(slots=True)
class Interruption:
    """Hold one operation's first interruption and whether it may still cancel the operation.

    Attributes
    ----------
    received : int | None
        First SIGINT or SIGTERM received while the operation's loop owned them, or None.
    owner : asyncio.Task[Any] | None
        Task running the operation, once it has started.
    cleaning : bool
        True once the operation's cleanup began; an interruption then waits for its completion.
    """

    received: int | None = None
    owner: asyncio.Task[Any] | None = None
    cleaning: bool = False


async def observe_exit(child: asyncio.subprocess.Process, observation: ProcessObservation) -> int:
    """Retain actual native completion time as soon as the owned child wait resolves.

    Parameters
    ----------
    child : asyncio.subprocess.Process
        Exact owned child, never a received PID.
    observation : ProcessObservation
        Fresh owning operation's private observation container.

    Returns
    -------
    int
        Actual native child exit, independent of later capture or validation.
    """
    result = await child.wait()
    observation.native_completed_at = datetime.now(UTC)
    observation.native_exit = result
    return result


async def capture(stream: asyncio.StreamReader, output: bytearray) -> bytes:
    """Drain one real pipe while enforcing its inclusive capture byte bound.

    Parameters
    ----------
    stream : asyncio.StreamReader
        Owned native stdout/stderr reader drained in 8192-byte blocks.
    output : bytearray
        Caller-owned bytearray retaining the actual bounded prefix as bytes arrive.

    Returns
    -------
    bytes
        Complete pipe bytes when native EOF arrives within MAX_CAPTURE.

    Raises
    ------
    Fault
        Raised as tool_output_limit before appending a block that exceeds the inclusive cap.
    """
    while block := await stream.read(8192):
        if len(output) + len(block) > MAX_CAPTURE:
            raise Fault("tool_output_limit")
        output.extend(block)
    return bytes(output)


async def terminate_group(child: asyncio.subprocess.Process, deadline: float) -> None:
    """Reap the exact exec group, leaving the main PID to its native asyncio waiter.

    Parameters
    ----------
    child : asyncio.subprocess.Process
        Actual native child/session group created by this invocation; unrelated PIDs are not signalled.
    deadline : float
        Absolute monotonic completion deadline shared by SIGTERM/SIGKILL, waiting and owned descendant reaping.

    Raises
    ------
    Fault
        Raised as tool_timeout when the owned group cannot finish within the original deadline.
    """
    for signum in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            return
        remaining = max(0.0, deadline - time.monotonic())
        grace = min(2.0, remaining / 2 if signum == signal.SIGTERM else remaining)
        stage_deadline = time.monotonic() + grace
        try:
            await asyncio.wait_for(asyncio.shield(child.wait()), timeout=grace)
        except TimeoutError:
            continue
        while time.monotonic() < stage_deadline:
            try:
                pid, _ = os.waitpid(-child.pid, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                await asyncio.sleep(0.01)
    try:
        await asyncio.wait_for(child.wait(), timeout=max(0.0, deadline - time.monotonic()))
    except TimeoutError as error:
        raise Fault("tool_timeout", exit_code=3) from error
    while time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(-child.pid, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            await asyncio.sleep(0.01)
    raise Fault("tool_timeout", exit_code=3)


async def execute(
    command: list[str],
    root: Path,
    total_deadline: float,
    cleanup: float,
    observation: ProcessObservation,
    environment: Mapping[str, str] | None = None,
    *,
    interruption: Interruption | None = None,
) -> ProcessResult:
    """Own an exec-only child, both readers and inclusive deadline-bounded cleanup.

    Parameters
    ----------
    command : list[str]
        Caller-authorised exec argv; no shell or repository-selected callback is used.
    root : Path
        Caller-authorised child working directory.
    total_deadline : float
        Absolute monotonic deadline including capture, wait and group cleanup.
    cleanup : float
        Seconds reserved within total_deadline for owned descendant termination.
    observation : ProcessObservation
        Fresh caller-owned raw pipe prefixes and native child exit container.
    environment : Mapping[str, str] | None
        Explicit trusted child environment, or inherited environment when None; original five-argument calls remain supported.
    interruption : Interruption | None
        The caller's interruption record; its cleanup marker is set before any owned cleanup begins.

    Returns
    -------
    ProcessResult
        Actual child exit plus complete bounded pipe bytes after owned resource cleanup.

    Raises
    ------
    Fault
        Raised for native exec unavailability, timeout, capture overflow or cleanup timeout; interruption propagates through cleanup.
    """
    try:
        child = await asyncio.create_subprocess_exec(
            *command,
            cwd=root,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=environment,
        )
    except OSError as error:
        raise Fault("tool_unavailable", exit_code=3) from error
    stdout = asyncio.create_task(
        capture(cast(asyncio.StreamReader, child.stdout), observation.stdout)
    )
    stderr = asyncio.create_task(
        capture(cast(asyncio.StreamReader, child.stderr), observation.stderr)
    )
    wait = asyncio.create_task(observe_exit(child, observation))
    tasks = (stdout, stderr, wait)
    try:
        observed = await asyncio.wait_for(
            asyncio.gather(*tasks),
            timeout=max(0.0, total_deadline - cleanup - time.monotonic()),
        )
        return ProcessResult(observed[2], observed[0], observed[1])
    except TimeoutError as error:
        raise Fault("tool_timeout", exit_code=3) from error
    finally:
        if interruption is not None:
            interruption.cleaning = True
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await terminate_group(child, total_deadline)
        finally:
            observation.native_exit = child.returncode
            if child.returncode is not None and observation.native_completed_at is None:
                observation.native_completed_at = datetime.now(UTC)


def run_interruptible(
    runner: asyncio.Runner,
    start: Callable[[], Coroutine[Any, Any, ProcessResult]],
    interruption: Interruption,
    previous_mask: set[int | signal.Signals],
) -> ProcessResult:
    """Run one operation while its own loop receives every interruption at an await.

    A handler that raises runs at whichever instruction is current, which inside the loop
    can be asyncio's own transport, pipe or child-watcher code: that code is then left
    half-connected, an unretrieved task exception reaches stderr, or the child's exit is
    never observed and the call waits for its deadline. Here SIGINT and SIGTERM only record
    the first interruption and cancel the operation at its next await, so its cleanup still
    terminates and reaps the owned group. A signal before the operation starts prevents it;
    one during cleanup or after completion does not cut the cleanup short.

    Parameters
    ----------
    runner : asyncio.Runner
        Fresh runner owned by this call, created while SIGINT and SIGTERM are blocked.
    start : Callable[[], Coroutine[Any, Any, ProcessResult]]
        Creates the operation only when no interruption preceded it.
    interruption : Interruption
        Fresh record shared with the operation's cleanup.
    previous_mask : set[int | signal.Signals]
        Caller's signal mask, restored for the loop and every child once the handlers are installed.

    Returns
    -------
    ProcessResult
        Result of an operation no interruption reached.

    Raises
    ------
    KeyboardInterrupt
        Raised after the operation's cleanup when SIGINT or SIGTERM arrived, with the signals
        blocked again and the caller's handlers restored.
    """
    loop = runner.get_loop()

    def cancel() -> None:
        """Cancel the started operation at its current await unless its cleanup began."""
        if interruption.owner is not None and not interruption.cleaning:
            interruption.owner.cancel()

    def receive(signum: int, frame: FrameType | None) -> None:
        """Record the first interruption and schedule its cancellation, raising nothing.

        Parameters
        ----------
        signum : int
            Received SIGINT or SIGTERM.
        frame : FrameType | None
            Interrupted frame, unused.
        """
        if interruption.received is None:
            interruption.received = signum
            loop.call_soon_threadsafe(cancel)

    async def operation() -> ProcessResult:
        """Start the operation in this task unless an interruption already arrived.

        Returns
        -------
        ProcessResult
            The operation's result.

        Raises
        ------
        asyncio.CancelledError
            Raised before the operation is created when an interruption preceded it.
        """
        interruption.owner = asyncio.current_task()
        if interruption.received is not None:
            raise asyncio.CancelledError
        return await start()

    previous = {signum: signal.signal(signum, receive) for signum in INTERRUPTS}
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            result = runner.run(operation())
        except asyncio.CancelledError:
            raise KeyboardInterrupt from None
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPTS)
        if interruption.received is not None:
            raise KeyboardInterrupt
        return result
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def run_process(
    command: list[str],
    root: Path,
    timeout: float = LEAF_SECONDS,
    *,
    observation: ProcessObservation | None = None,
    environment: Mapping[str, str] | None = None,
) -> ProcessResult:
    """Execute caller-authorised arguments with no shell or repository callback.

    The caller supplies trusted executable arguments and optional environment;
    repository input never selects them. Finite authorised programs qualify real process handling
    without claiming tool acceptance. Linux supplies owned descendant reaping.
    The synchronous API requires no running event loop on the calling thread;
    it owns its event loop and all resources until actual exit.
    Startup defers interruption until the loop belongs to its cleanup context;
    the caller's signal mask is restored before any child is started. On the main
    thread the loop receives SIGINT and SIGTERM while it runs (see run_interruptible),
    and an interruption reaches the caller as KeyboardInterrupt after cleanup.

    Parameters
    ----------
    command : list[str]
        Nonempty caller-authorised exec argv, never received repository instructions.
    root : Path
        Native child working directory supplied by the trusted caller.
    timeout : float
        Finite positive inclusive seconds, at most LEAF_SECONDS; includes owned cleanup.
    observation : ProcessObservation | None
        Optional fresh empty evidence container for actual stdout/stderr prefixes and native exit.
    environment : Mapping[str, str] | None
        Explicit trusted environment or inherited caller environment; caller signal masks are restored before exec.

    Returns
    -------
    ProcessResult
        Native exit/captures after reader tasks, child and owned Linux descendants finish.

    Raises
    ------
    Fault
        Raised for invalid budget/evidence reuse or an active caller loop, unavailable Linux/subreaper/exec, timeout or capture overflow.
    KeyboardInterrupt
        Raised after owned cleanup when SIGINT or SIGTERM interrupted the operation.
    """
    if (
        not command
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > LEAF_SECONDS
    ):
        raise Fault("configuration_invalid", exit_code=4)
    observed = observation if observation is not None else ProcessObservation()
    if (
        observed.stdout
        or observed.stderr
        or observed.native_exit is not None
        or observed.native_completed_at is not None
    ):
        raise Fault("configuration_invalid", exit_code=4)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise Fault("configuration_invalid", exit_code=4)
    total_deadline = time.monotonic() + timeout
    cleanup = min(4.0, timeout / 2)
    if os.name != "posix" or not Path("/proc/self").is_dir():
        raise Fault("tool_unavailable", exit_code=3)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise Fault("tool_unavailable", exit_code=3)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, INTERRUPTS)
    try:
        with asyncio.Runner() as runner:
            if threading.current_thread() is not threading.main_thread():
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                return runner.run(
                    execute(command, root, total_deadline, cleanup, observed, environment)
                )
            interruption = Interruption()
            return run_interruptible(
                runner,
                lambda: execute(
                    command,
                    root,
                    total_deadline,
                    cleanup,
                    observed,
                    environment,
                    interruption=interruption,
                ),
                interruption,
                previous_mask,
            )
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
