# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check the proposed parser view with genuine unchanged upstream tooling."""

import fcntl
import subprocess
from contextlib import ExitStack
from pathlib import Path
from typing import cast

import pytest
import yaml

from local_scaffold.actionlint_view import actionlint_view
from local_scaffold.dependencies import native_tool
from local_scaffold.inputs import Json
from local_scaffold.reports import Fault
from tests.conftest import SOURCE, change, snapshots, source_python


def independent_yaml(path: Path) -> dict[str, Json]:
    """Observe actual producer input with an independent native YAML loader."""
    loaded = cast(dict[object, Json], yaml.safe_load(path.read_text()))
    return {"on" if key is True else str(key): value for key, value in loaded.items()}


def test_complete_view_and_real_tool(root: Path) -> None:
    """All seven full workflow objects survive the view except the six references."""
    before = snapshots(root)
    with actionlint_view(root) as directory:
        subprocess.run(["git", "init", "--quiet", "-b", "main", str(directory)], check=True)
        replacements = 0
        for original in sorted((root / ".github/workflows").glob("*.yml")):
            expected = independent_yaml(original)
            jobs = cast(dict[str, Json], expected["jobs"])
            for raw_job in jobs.values():
                job = cast(dict[str, Json], raw_job)
                if "uses" in job:
                    assert str(job["uses"]).startswith("$/.github/workflows/")
                    job["uses"] = "./" + str(job["uses"])[2:]
                    replacements += 1
            assert independent_yaml(directory / ".github/workflows" / original.name) == expected
        assert replacements == 6
        result = subprocess.run(
            [
                str(native_tool("actionlint")),
                *[str(p) for p in sorted((directory / ".github/workflows").glob("*.yml"))],
            ],
            cwd=directory,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert not result.stdout
    assert not directory.exists()
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "condition", ["valid", "open-limit", "write-limit", "interrupt", "git-configuration"]
)
def test_actual_fixed_actionlint_entrypoint(condition: str) -> None:
    """Exercise the real fixed producer and genuine owned-child OS recovery."""
    program = """import os,resource,signal,sys
sys.path.insert(0,sys.argv[1])
from local_scaffold.actionlint_view import main
condition=sys.argv[2]
prior_open=resource.getrlimit(resource.RLIMIT_NOFILE)
prior_write=resource.getrlimit(resource.RLIMIT_FSIZE)
if condition=='open-limit':
    resource.setrlimit(resource.RLIMIT_NOFILE,(3,prior_open[1]))
elif condition=='write-limit':
    signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE,(128,prior_write[1]))
elif condition=='interrupt':
    signal.signal(signal.SIGALRM,lambda *_:os.kill(os.getpid(),signal.SIGINT))
    signal.setitimer(signal.ITIMER_REAL,0.01)
elif condition=='git-configuration':
    os.environ.update(GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='core.sharedRepository',GIT_CONFIG_VALUE_0='invalid')
try:
    result=main()
finally:
    signal.setitimer(signal.ITIMER_REAL,0)
    resource.setrlimit(resource.RLIMIT_NOFILE,prior_open)
    resource.setrlimit(resource.RLIMIT_FSIZE,prior_write)
sys.exit(result)
"""
    lock = SOURCE / ".tool-cache/fixed-actionlint-entrypoint-tests.lock"
    assert not lock.is_symlink()
    with lock.open("a+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        before = set((SOURCE / ".tool-cache").glob("actionlint-view-*"))
        result = subprocess.run(
            source_python("-c", program, str(SOURCE / "tools"), condition),
            cwd=SOURCE,
            capture_output=True,
            timeout=120,
            check=False,
        )
        assert set((SOURCE / ".tool-cache").glob("actionlint-view-*")) == before
    assert (
        result.returncode
        == {"valid": 0, "open-limit": 3, "write-limit": 2, "interrupt": 3, "git-configuration": 2}[
            condition
        ]
    ), (result.stdout, result.stderr)
    assert not result.stdout
    assert (
        result.stderr
        == {
            "valid": b"",
            "open-limit": b"input_unavailable\n",
            "write-limit": b"",
            "interrupt": b"interrupted\n",
            "git-configuration": b"tool_failed\n",
        }[condition]
    )


def test_invalid_host_has_no_view(root: Path) -> None:
    """A refused raw inventory cannot be normalised into a passing producer input."""
    change(root, "workflow-policy.json", ("platform",), "github_enterprise_server")
    with pytest.raises(Fault), ExitStack() as stack:
        stack.enter_context(actionlint_view(root))
    assert not list((root / ".tool-cache").glob("actionlint-view-*"))


def test_caller_failure_recovers_owned_view(root: Path) -> None:
    """A real caller exception removes only the positively created temporary view."""
    sentinel = root / ".tool-cache/unrelated"
    sentinel.mkdir()
    (sentinel / "preserved").write_text("original")
    with pytest.raises(ValueError), actionlint_view(root) as directory:
        raise ValueError("Actual authorised caller interruption")
    assert not directory.exists()
    assert (sentinel / "preserved").read_text() == "original"


@pytest.mark.parametrize(
    "change_kind",
    ["reference", "permission", "job-environment", "policy", "formatting", "extra-file"],
)
def test_changed_originals_cannot_qualify_view(root: Path, change_kind: str) -> None:
    """Actual changed original bytes cannot qualify a genuine native0 view result."""
    directory: Path | None = None
    with pytest.raises(Fault) as error:
        with actionlint_view(root) as directory:
            subprocess.run(["git", "init", "--quiet", "-b", "main", str(directory)], check=True)
            if change_kind == "policy":
                change(root, "workflow-policy.json", ("platform",), "github-enterprise-server")
            elif change_kind == "extra-file":
                (root / ".github/workflows/unrequired.yml").write_text("name: Unrequired\n")
            elif change_kind == "formatting":
                path = root / ".github/workflows/ci.yml"
                path.write_text(path.read_text() + "\n# Actual original changed after acceptance\n")
            else:
                path = root / ".github/workflows/ci.yml"
                value = independent_yaml(path)
                jobs = cast(dict[str, Json], value["jobs"])
                job = cast(dict[str, Json], jobs["docs"])
                if change_kind == "reference":
                    job["uses"] = "$/.github/workflows/docs.yml@main"
                elif change_kind == "permission":
                    job["permissions"] = {"contents": "write"}
                else:
                    job["env"] = {"PIP_CONFIG_FILE": "received.cfg"}
                path.write_text(yaml.safe_dump(value, sort_keys=False))
            result = subprocess.run(
                [
                    str(native_tool("actionlint")),
                    *[str(p) for p in sorted((directory / ".github/workflows").glob("*.yml"))],
                ],
                cwd=directory,
                capture_output=True,
                timeout=10,
                check=False,
            )
            assert result.returncode == 0
            assert not result.stdout and not result.stderr
    assert error.value.exit_code == 2
    assert directory is not None and not directory.exists()


@pytest.mark.parametrize(
    "kind", ["invalid-native", "valid-native-forbidden-policy", "extra", "missing"]
)
def test_actual_view_drift_cannot_qualify_native(root: Path, kind: str) -> None:
    """Complete analyser bytes remain bound even when unchanged native tooling passes."""
    directory: Path | None = None
    with pytest.raises(Fault) as error:
        with actionlint_view(root) as directory:
            subprocess.run(["git", "init", "--quiet", "-b", "main", str(directory)], check=True)
            path = directory / ".github/workflows/pre-commit.yml"
            original_files = sorted((directory / ".github/workflows").glob("*.yml"))
            if kind == "extra":
                (directory / ".github/workflows/extra.yml").write_text(
                    "name: Actual extra view input\n"
                )
            elif kind == "missing":
                path.unlink()
            else:
                value = independent_yaml(path)
                jobs = cast(dict[str, Json], value["jobs"])
                job = cast(dict[str, Json], jobs["quality"])
                if kind == "invalid-native":
                    job["runs-on"] = False
                else:
                    job["permissions"] = {"contents": "write"}
                path.write_text(yaml.safe_dump(value, sort_keys=False))
            if kind != "missing":
                result = subprocess.run(
                    [str(native_tool("actionlint")), *[str(p) for p in original_files]],
                    cwd=directory,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                assert result.returncode == (1 if kind == "invalid-native" else 0)
    assert error.value.code == "source_identity_mismatch"
    assert directory is not None and not directory.exists()


def test_adopted_fixed_native_role(root: Path) -> None:
    """The adopted producer returns native0 only after full binding and owned cleanup."""
    from local_scaffold.actionlint_view import analyse

    before = snapshots(root)
    unrelated = root / ".tool-cache/unrelated-existing"
    unrelated.mkdir()
    (unrelated / "preserved").write_bytes(b"actual existing bytes")
    result = analyse(root)
    assert result.exit_code == 0 and not result.stdout and not result.stderr
    assert snapshots(root) == before
    assert not list((root / ".tool-cache").glob("actionlint-view-*"))
    assert (unrelated / "preserved").read_bytes() == b"actual existing bytes"


def test_fixed_role_cannot_accept_invalid_original(root: Path) -> None:
    """A received policy refusal propagates before a producer can qualify any view."""
    from local_scaffold.actionlint_view import analyse

    change(root, "workflow-policy.json", ("platform",), "github_enterprise_server")
    with pytest.raises(Fault) as error:
        analyse(root)
    assert error.value.code == "policy_refusal" and error.value.exit_code == 2
    assert not list((root / ".tool-cache").glob("actionlint-view-*"))


def test_fixed_role_inclusive_preparation_deadline(root: Path) -> None:
    """A genuinely expired preparation budget refuses and removes its own view."""
    from local_scaffold.actionlint_view import analyse

    with pytest.raises(Fault) as error:
        analyse(root, 0.000001)
    assert error.value.code == "tool_timeout" and error.value.exit_code == 3
    assert not list((root / ".tool-cache").glob("actionlint-view-*"))


@pytest.mark.parametrize("timeout", [0.0, -1.0, 121.0, float("nan"), float("inf"), True])
def test_fixed_role_budget_configuration(root: Path, timeout: float) -> None:
    """The fixed adapter rejects nonfinite and unauthorized budgets before setup."""
    from local_scaffold.actionlint_view import analyse

    with pytest.raises(Fault) as error:
        analyse(root, timeout)
    assert error.value.code == "configuration_invalid" and error.value.exit_code == 4
