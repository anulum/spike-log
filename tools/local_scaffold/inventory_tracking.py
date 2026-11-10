# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Validate actual Git index contents and ignored internal working paths."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from .inputs import read_text
from .policy import EXCLUDED, FORBIDDEN
from .processes import run_process
from .reports import Report, safe_location


def verify_tracking(root: Path, report: Report) -> None:
    """Require ignored internal paths and refuse tracked private/build inputs.

    Parameters
    ----------
    root : Path
        Validated inspected repository. Fixed installed Git arguments inspect its metadata as data.
    report : Report
        Receives missing Git, native failure, absent/negated private-ignore and tracked-private findings.

    Raises
    ------
    local_scaffold.reports.Fault
        Raised for unavailable/invalid ignore input or a native process deadline/capture failure.
    local_scaffold.reports.DiagnosticLimit
        Raised when the supplied report's remaining diagnostic budget is exhausted.

    Notes
    -----
    Root-anchored and unanchored forms of both required private patterns are accepted.
    The effective native match must be the directory rule itself, including when
    the private directory is absent. Other overriding patterns are refused.
    Native check-ignore uses no-index so tracking cannot conceal the ignore decision.
    Each fixed Git command retains its existing individual bounded-runner contract.
    """
    if not (root / ".git").is_dir():
        report.add("input_unavailable", ".git", 3)
        return
    rules = {line.strip().removeprefix("/") for line in read_text(root, ".gitignore").splitlines()}
    explicit = {"docs/internal/", "docs/internal/**"}.issubset(rules)
    if not explicit:
        report.add("repository_inventory.private-unignored", ".gitignore")
    command = [
        "git",
        "--no-pager",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "--git-dir=" + str(root / ".git"),
        "--work-tree=" + str(root),
    ]
    ignored = run_process(
        [*command, "check-ignore", "--no-index", "--verbose", "--", "docs/internal/"],
        root,
    )
    if ignored.exit_code not in (0, 1):
        report.add("tool_failed", ".git")
        return
    source, separator, path = ignored.stdout.rpartition(b"\t")
    directory_rule = (
        ignored.exit_code == 0
        and separator == b"\t"
        and source.rsplit(b":", 1)[-1] in {b"/docs/internal/", b"docs/internal/"}
        and path == b"docs/internal/\n"
    )
    if not directory_rule and explicit:
        report.add("repository_inventory.private-unignored", ".gitignore")
    observed = run_process([*command, "ls-files", "-z"], root)
    if observed.exit_code:
        report.add("tool_failed", ".git")
        return
    for raw_name in observed.stdout.split(b"\0"):
        if not raw_name:
            continue
        try:
            name = raw_name.decode("utf-8")
        except UnicodeError:
            report.add("policy_refusal")
            continue
        parts = PurePosixPath(name).parts
        if name.startswith("docs/internal/") or any(
            part in EXCLUDED or part in FORBIDDEN for part in parts
        ):
            report.add("repository_inventory.private-tracked", safe_location(name))
