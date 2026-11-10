# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Create bounded complete semantic views for local-reference workflow parsers.

The raw workflow policy must pass before a temporary view can be created. The
producer receives all original workflow fields with six equivalent same-commit
references. Raw producer observations and view observations remain distinct.
"""

from __future__ import annotations

import math
import shutil
import signal
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import yaml

from .cli import interrupted
from .dependencies import native_tool
from .inputs import Json, parse_yaml, read_bytes, relative_path
from .policy import HEADER, LEAF_SECONDS, WORKFLOW_POLICY
from .processes import ProcessResult, run_process
from .reports import Fault, Report
from .workflows import collect, verify_snapshot


def require_identity(observed: object, expected: object) -> None:
    """Apply the same exact identity refusal to parsed, delivered and original state.

    Parameters
    ----------
    observed : object
        Actual parsed value, delivered bytes or retained original state.
    expected : object
        Exact original state the observation must equal.

    Raises
    ------
    Fault
        Raised with source_identity_mismatch when complete states differ.
    """
    if observed != expected:
        raise Fault("source_identity_mismatch")


@contextmanager
def actionlint_view(root: Path) -> Iterator[Path]:
    """Yield an owned complete same-commit semantic view after strict raw acceptance.

    Exactly the six already validated cloud references receive the supported
    local spelling. Every parsed workflow field is preserved. No rule, finding,
    threshold, executable or producer binary is modified. The view is temporary
    and cannot authorise an unsupported host or a changed/missing/duplicate call.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.

    Yields
    ------
    Path
        Owned temporary workflow directory preserving every parsed field and the six accepted same-commit calls.

    Raises
    ------
    Fault
        Raised for rejected original workflows, changed delivered/original bytes or bounded input failure.
    """
    report = Report("workflow_policy")
    original = collect(root)
    accepted = verify_snapshot(original, report)
    if report.exit_code:
        raise Fault("policy_refusal", exit_code=report.exit_code)
    cache = relative_path(root, ".tool-cache")
    cache.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="actionlint-view-", dir=cache))
    try:
        target = directory / ".github/workflows"
        target.mkdir(parents=True)
        produced: dict[str, bytes] = {}
        for filename in WORKFLOW_POLICY["workflows"]:
            value = accepted[filename]
            jobs = cast(dict[str, Json], value["jobs"])
            for job_id, raw_job in jobs.items():
                expected = WORKFLOW_POLICY["jobs"][filename + "/" + job_id]
                if "uses" in expected:
                    job = cast(dict[str, Json], raw_job)
                    job["uses"] = "./" + expected["uses"][2:]
            header = "\n".join("# " + line for line in HEADER) + "\n\n"
            data = (header + yaml.safe_dump(value, sort_keys=False)).encode()
            require_identity(
                parse_yaml(data, ".github/workflows/" + filename, workflow=True), value
            )
            (target / filename).write_bytes(data)
            produced[filename] = data
        yield directory
        names: list[str] = []
        for path in target.iterdir():
            names.append(path.name)
            if len(names) > 7:
                raise Fault("source_identity_mismatch")
        if set(names) != set(produced):
            raise Fault("source_identity_mismatch")
        for filename, data in produced.items():
            require_identity(read_bytes(directory, ".github/workflows/" + filename, 102400), data)
        require_identity(collect(root), original)
    finally:
        shutil.rmtree(directory)


def analyse(root: Path, timeout: float = LEAF_SECONDS) -> ProcessResult:
    """Return the real producer result only after complete normal acceptance.

    Validation, complete representation, real Git setup, actual Actionlint and
    owned cleanup share the original inclusive leaf budget. Received inputs
    cannot select an executable, producer version, rule or command argument.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    timeout : float
        Inclusive seconds shared by validation, view creation, native Git/Actionlint and cleanup; positive and at most LEAF_SECONDS.

    Returns
    -------
    ProcessResult
        Actual Actionlint exit and bounded stdout/stderr, returned only after final complete identity checks.

    Raises
    ------
    Fault
        Raised for invalid budget, unavailable producer, exhausted deadline or identity mismatch.
    """
    if (
        isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > LEAF_SECONDS
    ):
        raise Fault("configuration_invalid", exit_code=4)
    deadline = time.monotonic() + timeout
    producer = native_tool("actionlint")
    with actionlint_view(root) as directory:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Fault("tool_timeout", exit_code=3)
        setup = run_process(
            [
                "git",
                "-c",
                "init.templateDir=",
                "-c",
                "core.hooksPath=/dev/null",
                "init",
                "--quiet",
                "-b",
                "main",
                str(directory),
            ],
            directory,
            remaining,
        )
        if setup.exit_code:
            raise Fault("tool_failed")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Fault("tool_timeout", exit_code=3)
        result = run_process(
            [
                str(producer),
                *[
                    str(directory / ".github/workflows" / name)
                    for name in WORKFLOW_POLICY["workflows"]
                ],
            ],
            directory,
            remaining,
        )
    if time.monotonic() >= deadline:
        raise Fault("tool_timeout", exit_code=3)
    return result


def main() -> int:
    """Analyse the fixed trusted checkout for the Make native-tool target.

    Returns
    -------
    int
        Native Actionlint exit for the trusted checkout, or the authored Fault exit on refusal/unavailability.
    """
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        result = analyse(Path(__file__).resolve().parents[2])
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.flush()
        return result.exit_code
    except Fault as fault:
        print(fault.code, file=sys.stderr)
        return fault.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3
    except OSError:
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous)
