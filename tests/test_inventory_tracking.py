# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise private-ignore and index contracts through actual Git and inventory."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from local_scaffold.inventory import verify_tracking
from local_scaffold.reports import DiagnosticLimit, Report
from tests.conftest import SOURCE, payload, run_guard


@pytest.mark.parametrize("form", ["rooted", "unrooted"])
@pytest.mark.parametrize("present", [True, False])
def test_actual_private_directory_ignored(root: Path, form: str, present: bool) -> None:
    """Both documented directory forms pass in working and fresh-checkout states."""
    private = root / "docs/internal"
    retained = root.parent / "retained-private"
    if not present:
        private.rename(retained)
    path = root / ".gitignore"
    lines = path.read_text().splitlines()
    if form == "unrooted":
        lines = [
            line.removeprefix("/")
            if line.strip().removeprefix("/") in {"docs/internal/", "docs/internal/**"}
            else line
            for line in lines
        ]
    path.write_text("\n".join(lines) + "\n")
    before = path.read_bytes()
    payload(run_guard("repository_inventory", root), 0)
    assert path.read_bytes() == before
    assert private.exists() is present
    if not present:
        assert retained.is_dir()


@pytest.mark.parametrize("missing", ["docs/internal/", "docs/internal/**", "both"])
def test_missing_private_rules_refused(root: Path, missing: str) -> None:
    """A genuine Git tree without either required root rule cannot pass."""
    path = root / ".gitignore"
    removed = {"docs/internal/", "docs/internal/**"} if missing == "both" else {missing}
    path.write_text(
        "\n".join(
            line
            for line in path.read_text().splitlines()
            if line.strip().removeprefix("/") not in removed
        )
        + "\n"
    )
    value = payload(run_guard("repository_inventory", root), 2)
    assert "repository_inventory.private-unignored" in [
        reason["code"] for reason in cast(list[dict[str, Json]], value["reasons"])
    ]


@pytest.mark.parametrize("present", [True, False])
def test_actual_parent_reinclusion_refused(root: Path, present: bool) -> None:
    """A descendant-only match cannot mask parent reinclusion, even before creation."""
    private = root / "docs/internal"
    retained = root.parent / "retained-private"
    if not present:
        private.rename(retained)
    path = root / ".gitignore"
    path.write_text(path.read_text() + "\n!docs/internal/\n")
    ignored = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "check-ignore",
            "--no-index",
            "--verbose",
            "--",
            "docs/internal/",
        ],
        capture_output=True,
        timeout=10,
    )
    assert ignored.returncode == 0
    assert ignored.stdout.endswith(b":/docs/internal/**\tdocs/internal/\n")
    value = payload(run_guard("repository_inventory", root), 2)
    assert "repository_inventory.private-unignored" in [
        reason["code"] for reason in cast(list[dict[str, Json]], value["reasons"])
    ]
    assert private.exists() is present
    if not present:
        assert retained.is_dir()


def test_actual_tracked_public_source_accepted(root: Path) -> None:
    """An ordinary maintained public file remains admissible in the actual index."""
    path = root / "README.md"
    before = path.read_bytes()
    subprocess.run(
        ["git", "-C", str(root), "add", "--", "README.md"], check=True, capture_output=True
    )
    payload(run_guard("repository_inventory", root), 0)
    assert path.read_bytes() == before
    indexed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    assert indexed.stdout == b"README.md\0"


@pytest.mark.parametrize(
    "name",
    ["docs/internal/fixture.txt", ".tool-cache/fixture.txt", "retained/BACKUP/fixture.txt"],
)
def test_actual_tracked_private_components_refused(root: Path, name: str) -> None:
    """Only owned inert fixture bytes enter a real index to exercise refusal."""
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join((SOURCE / "tools/check_repository_metadata.py").read_text().splitlines()[:7])
        + "\n"
    )
    subprocess.run(
        ["git", "-C", str(root), "add", "-f", "--", name], check=True, capture_output=True
    )
    value = payload(run_guard("repository_inventory", root), 2)
    assert any(
        reason["code"] == "repository_inventory.private-tracked" and reason["location"] == name
        for reason in cast(list[dict[str, Json]], value["reasons"])
    )


def test_actual_non_utf8_index_path_refused(root: Path) -> None:
    """An actual POSIX tracked filename cannot create an invalid public location."""
    name = os.fsdecode(b"owned-nonutf8-\xff.txt")
    (root / name).write_bytes(b"Owned filename input.\n")
    subprocess.run(["git", "-C", str(root), "add", "--", name], check=True, capture_output=True)
    value = payload(run_guard("repository_inventory", root), 2)
    assert any(
        reason["code"] == "policy_refusal" and reason["location"] is None
        for reason in cast(list[dict[str, Json]], value["reasons"])
    )


def test_absent_git_retained_unavailable(root: Path, tmp_path: Path) -> None:
    """A missing owned Git directory remains unavailable and is retained elsewhere."""
    retained = tmp_path / "retained-git"
    (root / ".git").rename(retained)
    value = payload(run_guard("repository_inventory", root), 3)
    assert retained.is_dir()
    assert any(
        reason["location"] == ".git" for reason in cast(list[dict[str, Json]], value["reasons"])
    )


@pytest.mark.parametrize("component", ["HEAD", "index"])
def test_actual_malformed_git_metadata_refused(root: Path, component: str) -> None:
    """Git itself rejects malformed owned HEAD or index bytes without a substitute tool."""
    path = root / ".git" / component
    path.write_bytes(b"Owned invalid Git metadata.\n")
    value = payload(run_guard("repository_inventory", root), 2)
    assert "tool_failed" in [
        reason["code"] for reason in cast(list[dict[str, Json]], value["reasons"])
    ]


def test_missing_ignore_input_is_unavailable(root: Path, tmp_path: Path) -> None:
    """An absent required ignore input is unavailable and its original bytes survive."""
    retained = tmp_path / "retained-ignore"
    before = (root / ".gitignore").read_bytes()
    (root / ".gitignore").rename(retained)
    payload(run_guard("repository_inventory", root), 3)
    assert retained.read_bytes() == before


def test_actual_shared_report_diagnostic_limit(root: Path) -> None:
    """The preserved public API stops after an actual input fills its report."""
    path = root / ".gitignore"
    path.write_text(
        "\n".join(
            line
            for line in path.read_text().splitlines()
            if line.strip().removeprefix("/") not in {"docs/internal/", "docs/internal/**"}
        )
        + "\n"
    )
    report = Report("repository_inventory")
    for _ in range(255):
        report.add("policy_refusal")
    with pytest.raises(DiagnosticLimit):
        verify_tracking(root, report)
    assert len(report.reasons) == 256
    assert report.reasons[-1]["code"] == "diagnostic_budget_exceeded"
