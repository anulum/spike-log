# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise the real Make secret scanner and refusal of received suppressions."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.dependencies import native_tool
from local_scaffold.orchestration import configured_roles
from local_scaffold.processes import run_process
from tests.conftest import payload, run_guard, snapshots


@pytest.fixture
def native_secret_root(root: Path) -> Path:
    """Copy the admitted native scanner into the actual isolated repository."""
    target = root / ".tool-cache/native/gitleaks/gitleaks"
    target.parent.mkdir(parents=True)
    shutil.copyfile(native_tool("gitleaks"), target)
    target.chmod(0o755)
    return root


def test_make_secret_scan_accepts_owned_source(native_secret_root: Path) -> None:
    """The real public target accepts unchanged inputs without writing source."""
    before = snapshots(native_secret_root)
    result = subprocess.run(
        ["make", "--no-print-directory", "secret-scan"],
        cwd=native_secret_root,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert snapshots(native_secret_root) == before


def test_make_secret_scan_refuses_inline_allow(native_secret_root: Path) -> None:
    """An input comment cannot suppress a detectable non-credential test string."""
    marker = "gh" + "p_" + hashlib.sha256(b"non-credential scanner boundary").hexdigest()[:36]
    path = native_secret_root / "credential-boundary.txt"
    path.write_text('token = "' + marker + '" # gitleaks:allow\n')
    before = snapshots(native_secret_root)
    result = subprocess.run(
        ["make", "--no-print-directory", "secret-scan"],
        cwd=native_secret_root,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 2
    assert b"secret-scan] Error 1\n" in result.stderr
    assert marker.encode() not in result.stdout + result.stderr
    assert snapshots(native_secret_root) == before


def test_make_secret_scan_refuses_repository_ignore(native_secret_root: Path) -> None:
    """The actual reported fingerprint cannot disable the public required target."""
    marker = "gh" + "p_" + hashlib.sha256(b"non-credential scanner boundary").hexdigest()[:36]
    path = native_secret_root / "credential-boundary.txt"
    path.write_text('token = "' + marker + '"\n')
    output = native_secret_root / ".tool-cache/security/secret-scan.json"
    result = subprocess.run(
        [
            str(native_secret_root / ".tool-cache/native/gitleaks/gitleaks"),
            "dir",
            "--redact",
            "--no-banner",
            "--log-level",
            "error",
            "--ignore-gitleaks-allow",
            "--gitleaks-ignore-path",
            "/dev/null",
            "--config",
            str(native_secret_root / "gitleaks.toml"),
            "--report-format",
            "json",
            "--report-path",
            str(output),
            ".",
        ],
        cwd=native_secret_root,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 1
    findings = cast(list[dict[str, object]], json.loads(output.read_bytes()))
    assert len(findings) == 1 and findings[0]["RuleID"] == "github-pat"
    fingerprint = findings[0]["Fingerprint"]
    assert isinstance(fingerprint, str) and fingerprint
    assert marker.encode() not in output.read_bytes() + result.stdout + result.stderr
    (native_secret_root / ".gitleaksignore").write_text(fingerprint + "\n")
    before = snapshots(native_secret_root)
    required = subprocess.run(
        ["make", "--no-print-directory", "secret-scan"],
        cwd=native_secret_root,
        capture_output=True,
        timeout=20,
    )
    assert required.returncode == 2
    assert b"secret-scan] Error 1\n" in required.stderr
    assert marker.encode() not in required.stdout + required.stderr
    assert snapshots(native_secret_root) == before


def test_make_secret_scan_refuses_missing_producer(root: Path) -> None:
    """An absent native scanner leaves the actual required Make target failed."""
    before = snapshots(root)
    result = subprocess.run(
        ["make", "--no-print-directory", "secret-scan"],
        cwd=root,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 2
    assert b"secret-scan] Error 127\n" in result.stderr
    assert not (root / ".tool-cache/native/gitleaks/gitleaks").exists()
    assert snapshots(root) == before


def test_configured_secret_role_scans_received_cache_source(native_secret_root: Path) -> None:
    """A cache ancestor must not hide received public inputs from the genuine role."""
    role = {role.name: role for role in configured_roles(native_secret_root)}["secret_scan"]
    clean = run_process(list(role.command), role.working_directory or native_secret_root, 20)
    assert clean.exit_code == 0, (clean.stdout, clean.stderr)
    marker = "gh" + "p_" + hashlib.sha256(b"non-credential scanner boundary").hexdigest()[:36]
    (native_secret_root / "credential-boundary.txt").write_text('token = "' + marker + '"\n')
    before = snapshots(native_secret_root)
    result = run_process(list(role.command), role.working_directory or native_secret_root, 20)
    assert result.exit_code == 1, (result.stdout, result.stderr)
    assert marker.encode() not in result.stdout + result.stderr
    assert snapshots(native_secret_root) == before


@pytest.mark.parametrize("kind", ["file", "dangling-link"])
def test_public_preflight_refuses_received_ignore(root: Path, kind: str) -> None:
    """Received suppression files or dangling links refuse before any native role."""
    path = root / ".gitleaksignore"
    if kind == "file":
        path.write_text("# Received source cannot select the suppression policy.\n")
    else:
        path.symlink_to(root / "absent-suppression-input")
    before = snapshots(root)
    report = payload(run_guard("preflight", root, "--profile", "local-scaffold"), 2)
    assert report["reasons"] == [
        {
            "code": "policy_refusal",
            "detail": "Required local infrastructure condition failed: policy_refusal.",
            "location": ".gitleaksignore",
        }
    ]
    checks = report["checks"]
    assert isinstance(checks, list) and len(checks) == 18
    assert all(isinstance(check, dict) and check["status"] == "not_run" for check in checks)
    assert snapshots(root) == before
