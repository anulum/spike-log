# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Verify real test entry points retain the complete maintained-source denominator."""

import json
import os
import shlex
import subprocess
from pathlib import Path

import pytest

from local_scaffold.orchestration import configured_roles
from tests.conftest import SOURCE


@pytest.mark.parametrize("entry_point", ["make", "configured-role"])
def test_targeted_entry_retains_complete_coverage_scope(tmp_path: Path, entry_point: str) -> None:
    """Pass one real schema test while refusing incomplete tools and tests coverage.

    Parameters
    ----------
    tmp_path : Path
        Owned directory for the native report, coverage data and child test cache.
    entry_point : str
        Genuine Make target or actual configured role with only selection and
        temporary-directory arguments narrowed for this authorised targeted run.
    """
    selection = "tests/test_repository_metadata.py::test_complete_genuine_schema_oracle"
    report_path = tmp_path / "native-coverage.json"
    child_temp = tmp_path / "child-tests"
    environment = os.environ.copy()
    environment["COVERAGE_FILE"] = str(tmp_path / "native-coverage-data")
    environment["PYTHONWARNINGS"] = "always::ResourceWarning"
    environment["PYTEST_ADDOPTS"] = shlex.join(
        [
            "--cov-report=json:" + str(report_path),
            "--override-ini",
            "cache_dir=" + str(tmp_path / "child-pytest-cache"),
        ]
    )
    if entry_point == "make":
        command = [
            "make",
            "--no-print-directory",
            "test",
            "TEST_SELECTION=" + selection,
            "TEST_BASETEMP=" + str(child_temp),
            "TEST_WORKERS=0",
        ]
        expected_exit = 2
    else:
        role = next(
            item
            for item in configured_roles(SOURCE)
            if item.name == "infrastructure_tests_coverage"
        )
        command = list(role.command)
        assert command[-1] == str(SOURCE / "tests")
        command[-1] = selection
        temporary_argument = command.index("--basetemp=.tool-cache/test-runs")
        command[temporary_argument] = "--basetemp=" + str(child_temp)
        expected_exit = 1
    result = subprocess.run(
        command,
        cwd=SOURCE,
        env=environment,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == expected_exit, (result.stdout, result.stderr)
    assert "1 passed" in result.stdout, (result.stdout, result.stderr)
    assert "ResourceWarning:" not in result.stderr, result.stderr
    report = json.loads(report_path.read_bytes())
    expected_sources = {
        str(path.relative_to(SOURCE))
        for root in ("tools", "tests")
        for path in (SOURCE / root).rglob("*.py")
    }
    assert set(report["files"]) == expected_sources
    assert (
        sum(
            report["files"][path]["summary"]["missing_lines"]
            for path in expected_sources
            if path.startswith("tests/")
        )
        > 0
    )
    assert report["totals"]["percent_covered"] < 100
