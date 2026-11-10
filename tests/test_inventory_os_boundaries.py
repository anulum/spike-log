# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise real traversal, entry kinds, Git bytes and refused generation."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from local_scaffold.reports import validate_child
from tests.conftest import SOURCE, change, payload, run_guard


@pytest.mark.parametrize(
    "case",
    [
        "absent-git",
        "invalid-git",
        "denied-directory",
        "control-name",
        "tracked-cache",
        "tracked-nonutf8",
        "required-fifo",
        "total-size",
    ],
)
def test_actual_inventory_os_and_git_refusals(root: Path, case: str) -> None:
    """Real kernel and Git observations retain authored finite refusal reasons."""
    denied: Path | None = None
    expected = 3 if case in ("absent-git", "denied-directory") else 2
    code = {
        "absent-git": "input_unavailable",
        "invalid-git": "tool_failed",
        "denied-directory": "input_unavailable",
        "control-name": "policy_refusal",
        "tracked-cache": "repository_inventory.private-tracked",
        "tracked-nonutf8": "policy_refusal",
        "required-fifo": "repository_inventory.special-file",
        "total-size": "resource_limit",
    }[case]
    try:
        if case in ("absent-git", "invalid-git"):
            shutil.rmtree(root / ".git")
            if case == "invalid-git":
                (root / ".git").mkdir()
        elif case == "denied-directory":
            assert os.geteuid() != 0
            denied = root / "unreadable"
            denied.mkdir()
            (denied / "preserved").write_bytes(b"unreadable original")
            denied.chmod(0)
        elif case == "control-name":
            (root / "actual-\x1b-control").write_bytes(b"actual harmless contents")
        elif case == "tracked-cache":
            (root / ".tool-cache/actual-tracked.txt").write_bytes(b"actual private cache input")
            subprocess.run(
                ["git", "-C", str(root), "add", "-f", ".tool-cache/actual-tracked.txt"],
                capture_output=True,
                check=True,
            )
        elif case == "tracked-nonutf8":
            name = os.fsencode(root) + b"/actual-invalid-\xff"
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(descriptor, b"actual harmless contents")
            os.close(descriptor)
            subprocess.run(
                [b"git", b"-C", os.fsencode(root), b"add", b"--", b"actual-invalid-\xff"],
                capture_output=True,
                check=True,
            )
        elif case == "required-fifo":
            (root / "README.md").unlink()
            os.mkfifo(root / "README.md")
        else:
            for index in range(9):
                with (root / ("sparse-" + str(index))).open("wb") as stream:
                    stream.truncate(16777216)
        result = run_guard("repository_inventory", root)
        report = validate_child(
            payload(result, expected), "repository_inventory", result.returncode
        )
        assert any(reason["code"] == code for reason in report["reasons"])
        assert all(reason["code"] != "unexpected_fault" for reason in report["reasons"])
    finally:
        if denied is not None:
            denied.chmod(0o700)
            assert (denied / "preserved").read_bytes() == b"unreadable original"


def test_actual_refused_metadata_cannot_publish(root: Path) -> None:
    """A real metadata policy failure leaves no output or owned temporary file."""
    change(root, "repository-domain.json", ("repository_name",), "FOREIGN-REPOSITORY")
    result = run_guard(
        "repository_inventory", root, "--mode", "generate", "--output", "refused.json"
    )
    report = payload(result, 2)
    assert report["scope"] == "inventory_generate"
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "repository_metadata.wrong-identity"
        for reason in reasons
    )
    assert not (root / "refused.json").exists()
    assert not list(root.glob(".spike-log-inventory-*"))


def test_actual_unavailable_input_at_diagnostic_boundary(root: Path) -> None:
    """The real provenance CLI preserves native3 after255 prior native2 findings."""
    assert os.geteuid() != 0
    for index in range(127):
        (root / ("aa-unlicensed-" + str(index) + ".py")).write_text(
            '"""Actual unlicensed file."""\n'
        )
    header = "\n".join((SOURCE / "tools/preflight.py").read_text().splitlines()[:7])
    (root / "ab-conflicting.py").write_text(header + "\n# SPDX-License-Identifier" + ": MIT\n")
    unreadable = root / "zz-unavailable.txt"
    unreadable.write_bytes(b"actual denied original")
    unreadable.chmod(0)
    try:
        result = run_guard("source_provenance", root)
        report = validate_child(payload(result, 3), "source_provenance", result.returncode)
        assert len(report["reasons"]) == 256
        assert report["reasons"][-1]["code"] == "diagnostic_budget_exceeded"
    finally:
        unreadable.chmod(0o600)
        assert unreadable.read_bytes() == b"actual denied original"
