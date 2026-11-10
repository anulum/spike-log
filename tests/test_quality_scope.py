# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise complete native collection and received-ignore refusal boundaries."""

import subprocess
import sys
from pathlib import Path

import pytest

from local_scaffold.orchestration import configured_roles
from local_scaffold.processes import run_process
from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python
from tests.test_atomic_publication import actual_strace as actual_strace


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("received.py", 2),
        ("examples/received.py", 2),
        ("tools/.hidden/received.py", 2),
        ("tools/received.PY", 2),
        ("tools_extra/received.py", 2),
        ("tools/site-packages/received.py", 2),
        ("tests/shadowed.py", 2),
        ("received.pyi", 2),
        ("tools/received.py", 0),
        ("tests/received.pyi", 0),
    ],
)
def test_python_source_requires_current_native_enrollment(
    root: Path, relative: str, expected: int
) -> None:
    """Refuse uncollected Python instead of silently certifying a smaller scope.

    Parameters
    ----------
    root : Path
        Actual isolated repository input to the maintained inventory CLI.
    relative : str
        Source spelling whose native enrollment is independently expected.
    expected : int
        Zero for supported current roots or two for unexamined source.
    """
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    header = (SOURCE / "tools/check_repository_inventory.py").read_text().split('"""', 1)[0]
    target.write_text(header + '"""Actual received source under inspection."""\nobserved = 1\n')
    if relative == "tests/shadowed.py":
        target.with_suffix(".pyi").write_text(
            header + '"""Typed interface shadowing a separate implementation."""\nobserved: int\n'
        )
    before = snapshots(root)
    value = payload(run_guard("repository_inventory", root), expected)
    if expected:
        reasons = value["reasons"]
        assert isinstance(reasons, list)
        assert any(
            isinstance(reason, dict) and reason["code"] == "scan_incomplete" for reason in reasons
        )
    assert snapshots(root) == before


@pytest.mark.parametrize(
    ("role_name", "body", "ignored_by_git"),
    [
        ("python_lint", "import math\n", True),
        ("python_format", "observed=1\n", True),
        ("python_lint", "import math\n", False),
        ("python_format", "observed=1\n", False),
        (
            "python_native_documentation",
            "def observed(value: int) -> int:\n    return value\n",
            False,
        ),
        (
            "python_native_documentation",
            "def observed(value: int) -> int:\n    return value\n",
            True,
        ),
    ],
)
def test_received_git_ignore_cannot_suppress_native_quality(
    root: Path, role_name: str, body: str, ignored_by_git: bool
) -> None:
    """Find actual native violations through configured roles and Make quality.

    Parameters
    ----------
    root : Path
        Actual source input containing a known native violation.
    role_name : str
        Independently selected supported Ruff role.
    body : str
        Finite lint, format or documentation violation that is never executed.
    ignored_by_git : bool
        Test a received Git exclusion, or a nonprivate directory excluded by native defaults.
    """
    target = root / (
        "tools/received_quality.py" if ignored_by_git else "tools/dist/received_quality.py"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    header = (SOURCE / "tools/check_repository_inventory.py").read_text().split('"""', 1)[0]
    target.write_text(header + '"""Actual native quality adverse input."""\n' + body)
    ignore = root / ".gitignore"
    if ignored_by_git:
        ignore.write_text(ignore.read_text() + "\ntools/received_quality.py\n")
    original = (target.read_bytes(), ignore.read_bytes())
    role = {item.name: item for item in configured_roles(root)}[role_name]
    result = run_process(list(role.command), role.working_directory or root)
    assert result.exit_code == 1, (result.stdout, result.stderr)
    assert target.name.encode() in result.stdout, (result.stdout, result.stderr)
    made = subprocess.run(
        ["make", "--no-print-directory", "quality", "PYTHON=" + sys.executable],
        cwd=root,
        capture_output=True,
        timeout=45,
    )
    assert made.returncode == 2, (made.stdout, made.stderr)
    assert target.name.encode() in made.stdout, (made.stdout, made.stderr)
    assert (target.read_bytes(), ignore.read_bytes()) == original


def test_paired_interface_check_does_not_follow_received_link(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """Observe actual no-follow syscalls instead of only checking refusal status.

    Parameters
    ----------
    root : Path
        Actual repository with a received Python implementation and sibling link.
    tmp_path : Path
        Owned area containing a sentinel outside the inspected repository.
    actual_strace : Path
        Genuine pinned native syscall observer tracing only the guard process.
    """
    outside = tmp_path / "outside_interface.pyi"
    original = b"Owned outside sentinel.\n"
    outside.write_bytes(original)
    implementation = root / "tools/received_shadow.py"
    header = (SOURCE / "tools/check_repository_inventory.py").read_text().split('"""', 1)[0]
    implementation.write_text(header + '"""Actual source under inspection."""\nobserved = 1\n')
    interface = implementation.with_suffix(".pyi")
    interface.symlink_to(outside)
    trace = tmp_path / "interface-stat.native-trace"
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "--kill-on-exit",
            "-o",
            str(trace),
            "-e",
            "trace=stat,lstat,newfstatat,statx",
            *source_python(
                str(SOURCE / "tools/check_repository_inventory.py"),
                "--root",
                str(root),
                "--json",
            ),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    payload(result, 2)
    calls = [line for line in trace.read_text().splitlines() if '"' + str(interface) + '"' in line]
    assert calls
    assert all("lstat(" in call or "AT_SYMLINK_NOFOLLOW" in call for call in calls), calls
    assert interface.is_symlink() and outside.read_bytes() == original
