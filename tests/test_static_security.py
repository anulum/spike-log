# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual Make and configured source-security suppression boundaries."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from local_scaffold.orchestration import Role, configured_roles, run_plan
from local_scaffold.processes import run_process
from local_scaffold.reports import Report, validate_child


@pytest.mark.parametrize("kind", ["clean", "finding", "inline", "ini", "both"])
def test_configured_static_security_checks_received_source(root: Path, kind: str) -> None:
    """Retain actual scanner findings through Make, fixed policy and aggregation.

    Parameters
    ----------
    root : Path
        Actual isolated source checkout supplying scanned files as data.
    kind : str
        Clean input or a concrete assert finding with attempted suppressions.
    """
    if kind != "clean":
        suffix = "  # nosec B101" if kind in ("inline", "both") else ""
        (root / "tools/owned_static_security_case.py").write_text(
            '"""Parser-only adverse source; never executed."""\nassert True' + suffix + "\n"
        )
    if kind in ("ini", "both"):
        for location in (root / ".bandit", root / "tools/.bandit"):
            location.write_text("[bandit]\nskips=B101\n")
    made = subprocess.run(
        ["make", "--no-print-directory", "source-analysis", "PYTHON=" + sys.executable],
        cwd=root,
        capture_output=True,
        timeout=30,
    )
    assert made.returncode == (0 if kind == "clean" else 2), (made.stdout, made.stderr)
    findings = json.loads((root / ".tool-cache/bandit.json").read_bytes())["results"]
    assert any(item["test_id"] == "B101" for item in findings) == (kind != "clean")
    roles = configured_roles(root)
    security = next(role for role in roles if role.name == "python_security")
    result = run_process(list(security.command), security.working_directory or root, 15)
    assert result.exit_code == (0 if kind == "clean" else 1)
    assert any(item["test_id"] == "B101" for item in json.loads(result.stdout)["results"]) == (
        kind != "clean"
    )
    report = Report("preflight")
    finite = tuple(
        security
        if role.name == "python_security"
        else Role(role.name, (sys.executable, "-I", "-c", "pass"))
        for role in roles
    )
    run_plan(root, report, finite, 15)
    expected = 0 if kind == "clean" else 2
    assert report.exit_code == expected
    value = validate_child(report.payload(), "preflight", expected)
    observed = next(item for item in value["checks"] if item["role"] == "python_security")
    assert observed["exit_code"] == expected
    assert len(value["checks"]) == 18


@pytest.mark.parametrize("kind", ["cache", "output", "dangling"])
def test_static_security_output_links_refuse(root: Path, tmp_path: Path, kind: str) -> None:
    """Keep native scanner output within the owned cache without following links.

    Parameters
    ----------
    root : Path
        Actual isolated source checkout invoking the maintained Make target.
    tmp_path : Path
        Owned directory containing unrelated sentinel data for the boundary.
    kind : str
        Cache directory link, existing output link or dangling output link.
    """
    unrelated = tmp_path / "unrelated-source-analysis"
    unrelated.mkdir()
    target = unrelated / "bandit.json"
    original = b"Unrelated original bytes.\\n"
    if kind != "dangling":
        target.write_bytes(original)
    cache = root / ".tool-cache"
    if kind == "cache":
        shutil.rmtree(cache)
        cache.symlink_to(unrelated, target_is_directory=True)
    else:
        (cache / "bandit.json").symlink_to(target)
    result = subprocess.run(
        ["make", "--no-print-directory", "source-analysis", "PYTHON=" + sys.executable],
        cwd=root,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0, (
        result.stdout,
        result.stderr,
        target.exists(),
        target.read_bytes()[:60] if target.exists() else b"",
    )
    if kind == "dangling":
        assert not target.exists()
    else:
        assert target.read_bytes() == original
