# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — actual pre-mutation environment checks

"""Exercise genuine frozen inputs through public API, CLI and Make boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from check_environment_inputs import main
from local_scaffold.bootstrap_bindings import SOURCE_PINS
from local_scaffold.bootstrap_inputs import verify
from local_scaffold.reports import Fault
from tests.conftest import SOURCE, source_python
from tests.test_provenance_local import INPUTS, OWNER

SOURCE_INPUTS = Path(os.environ.get("SPIKE_LOG_TEST_ENVIRONMENT_SOURCE", str(SOURCE)))
UNSUPPORTED_PYTHON = (
    SOURCE / ".tool-cache/native-fixtures/cpython-3.13.15/extracted/python/bin/python3.13"
)
UNSUPPORTED_ENVIRONMENT = (
    SOURCE / ".tool-cache/native-fixtures/cpython-3.13.15/guard-environment-uv/bin/python"
)


@dataclass(frozen=True)
class EnvironmentInputs:
    """Retain independently selected genuine operands and an unused destination.

    Parameters
    ----------
    root : Path
        Source-identical tool checkout with the frozen proposed input files.
    artifacts : Path
        Owned hardlinks to original artifacts; derivatives unlink before writing.
    owner : Path
        Independently supplied original owner tree.
    environment : Path
        Destination inspected only as data during these checks.
    """

    root: Path
    artifacts: Path
    owner: Path
    environment: Path


@pytest.fixture
def inputs(tmp_path: Path) -> EnvironmentInputs:
    """Relocate actual tool code and immutable data without creating an environment."""
    root = tmp_path / "project"
    root.mkdir()
    shutil.copyfile(SOURCE / "Makefile", root / "Makefile")
    shutil.copytree(SOURCE / ".make", root / ".make")
    shutil.copytree(SOURCE / "tools", root / "tools", ignore=shutil.ignore_patterns("__pycache__"))
    for name, digest in SOURCE_PINS.items():
        original = SOURCE_INPUTS / name
        assert hashlib.sha256(original.read_bytes()).hexdigest() == digest
        shutil.copyfile(original, root / name)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    for original in INPUTS.iterdir():
        assert original.is_file() and not original.is_symlink()
        os.link(original, artifacts / original.name)
    return EnvironmentInputs(root, artifacts, OWNER, root / ".venv")


def snapshot(root: Path) -> dict[str, tuple[str, bytes]]:
    """Retain all paths and original bytes, including empty dirs and any generated cache."""
    result = {}
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = ("link", os.readlink(path).encode())
        elif path.is_dir():
            result[name] = ("directory", b"")
        else:
            result[name] = ("file", path.read_bytes())
    return result


def arguments(inputs: EnvironmentInputs) -> list[str]:
    """Select data roots explicitly without supplying executable callbacks."""
    return [
        "--root",
        str(inputs.root),
        "--artifacts",
        str(inputs.artifacts),
        "--owner-source",
        str(inputs.owner),
        "--environment",
        str(inputs.environment),
        "--json",
    ]


def invoke(
    inputs: EnvironmentInputs, *extra: str, instrument: bool = True, python: str = sys.executable
) -> subprocess.CompletedProcess[bytes]:
    """Run the real public script under ``python``, measured as an owned child unless not instrumented."""
    script = [str(SOURCE / "tools/check_environment_inputs.py"), *arguments(inputs), *extra]
    if instrument:
        command = source_python("-B", "-I", *script, executable=python)
    else:
        command = [python, "-B", "-I", *script]
    return subprocess.run(
        command,
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )


def test_public_api_and_actual_make_check_leave_all_state_unchanged(
    inputs: EnvironmentInputs, capsys: pytest.CaptureFixture[str]
) -> None:
    """A complete real input set passes without an environment or tool cache."""
    before = snapshot(inputs.root)
    assert main(arguments(inputs)) == 0
    assert json.loads(capsys.readouterr().out)["gate"] == "environment_inputs"
    direct = invoke(inputs, instrument=False)
    assert direct.returncode == 0, (direct.stdout, direct.stderr)
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "check-environment-inputs",
            "BASE_PYTHON=" + sys.executable,
            "ENVIRONMENT_INPUTS=" + str(inputs.artifacts),
            "ENVIRONMENT_OWNER_SOURCE=" + str(inputs.owner),
        ],
        cwd=inputs.root,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert json.loads(result.stdout.splitlines()[-1])["status"] == "passed"
    assert snapshot(inputs.root) == before
    assert not inputs.environment.exists() and not (inputs.root / ".tool-cache").exists()


@pytest.mark.parametrize("target", ["environment", "prepare-uv", "check-environment-inputs"])
@pytest.mark.parametrize("package", ["evidence-manifest-toolkit", "rfc8785"])
@pytest.mark.parametrize("change", ["absent", "corrupt"])
def test_actual_bootstrap_local_artifact_failure_precedes_every_write(
    inputs: EnvironmentInputs, target: str, package: str, change: str
) -> None:
    """Missing or corrupt original local wheels stop real targets before UV or env writes."""
    baseline = json.loads((inputs.root / "dependency-provenance.json").read_bytes())
    selected = next(row for row in baseline["packages"] if row["name"] == package)[
        "source_artifact"
    ]
    artifact = inputs.artifacts / selected["filename"]
    original = INPUTS / artifact.name
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    artifact.unlink()
    if change == "corrupt":
        artifact.write_bytes(b"Actual corrupt selected wheel bytes.\n")
    before = snapshot(inputs.root)
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            target,
            "BASE_PYTHON=" + sys.executable,
            "ENVIRONMENT_INPUTS=" + str(inputs.artifacts),
            "ENVIRONMENT_OWNER_SOURCE=" + str(inputs.owner),
        ],
        cwd=inputs.root,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2, (result.stdout, result.stderr)
    report = json.loads(result.stdout.splitlines()[-1])
    assert report["exit_code"] == (3 if change == "absent" else 2)
    assert report["reasons"][0]["code"] == (
        "input_unavailable" if change == "absent" else "source_identity_mismatch"
    )
    assert snapshot(inputs.root) == before
    assert not inputs.environment.exists() and not (inputs.root / ".tool-cache").exists()
    assert hashlib.sha256(original.read_bytes()).hexdigest() == digest


@pytest.mark.parametrize(
    "change",
    [
        "missing-uv",
        "missing-builder",
        "bad-manifest",
        "missing-build-evidence",
        "missing-response",
        "wrong-lock",
        "bad-runtime-lock",
        "small-budget",
        "large-budget",
    ],
)
def test_full_selected_input_and_resource_failures(inputs: EnvironmentInputs, change: str) -> None:
    """Actual selected artifact, source and caller-budget failures remain read only."""
    baseline = json.loads((inputs.root / "dependency-provenance.json").read_bytes())
    extra: list[str] = []
    if change in {"missing-uv", "missing-builder"}:
        name = "uv" if change == "missing-uv" else "poetry-core"
        selected = next(row for row in baseline["packages"] if row["name"] == name)
        (inputs.artifacts / selected["source_artifact"]["filename"]).unlink()
    elif change in {"bad-manifest", "missing-build-evidence", "missing-response"}:
        name = {
            "bad-manifest": "owner-source-inputs.json",
            "missing-build-evidence": "common-build-producer.json",
            "missing-response": "evidence-manifest-toolkit.json",
        }[change]
        path = inputs.artifacts / name
        path.unlink()
        if change == "bad-manifest":
            path.write_bytes(b"Actual changed original source manifest.\n")
    elif change in {"wrong-lock", "bad-runtime-lock"}:
        name = "requirements-dev.txt" if change == "wrong-lock" else "requirements-runtime.txt"
        (inputs.root / name).write_bytes(b"Actual changed lock.\n")
    else:
        extra = ["--max-input-bytes", "1" if change == "small-budget" else "134217729"]
    before = snapshot(inputs.root)
    result = invoke(inputs, *extra)
    expected = 3 if change.startswith("missing-") else 4 if change == "large-budget" else 2
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["exit_code"] == expected
    assert not result.stderr
    assert snapshot(inputs.root) == before


@pytest.mark.parametrize(
    "state",
    [
        "empty",
        "file",
        "nonempty",
        "linked",
        "inside-artifacts",
        "inside-owner",
        "contains-artifacts",
        "contains-owner",
        "matching",
        "missing-interpreter",
        "wrong-interpreter",
        "wrong-version",
        "duplicate-version",
        "system-site",
    ],
)
def test_existing_destination_is_checked_without_execution(
    inputs: EnvironmentInputs, state: str
) -> None:
    """Real destination layouts never cause an interpreter launch or a mutation."""
    target = inputs.environment
    if state == "file":
        target.write_bytes(b"Existing unrelated file.\n")
    elif state == "linked":
        target.symlink_to(inputs.root, target_is_directory=True)
    elif state == "inside-artifacts":
        inputs = EnvironmentInputs(
            inputs.root, inputs.artifacts, inputs.owner, inputs.artifacts / "env"
        )
    elif state == "inside-owner":
        inputs = EnvironmentInputs(
            inputs.root, inputs.artifacts, inputs.owner, inputs.owner / "env"
        )
    elif state in {"contains-artifacts", "contains-owner"}:
        tree = inputs.artifacts if state == "contains-artifacts" else inputs.owner
        inputs = EnvironmentInputs(inputs.root, inputs.artifacts, inputs.owner, tree.parent)
    else:
        target.mkdir()
        if state == "nonempty":
            (target / "original").write_bytes(b"Retained original.\n")
        elif state != "empty":
            text = (Path(sys.prefix) / "pyvenv.cfg").read_text()
            if state == "wrong-version":
                text = text.replace("version_info = 3.13.18", "version_info = 3.13.16")
            elif state == "duplicate-version":
                text += "\nversion_info = 3.13.18\n"
            elif state == "system-site":
                text = text.replace(
                    "include-system-site-packages = false", "include-system-site-packages = true"
                )
            (target / "pyvenv.cfg").write_text(text)
            (target / "bin").mkdir()
            interpreter = (
                UNSUPPORTED_PYTHON if state == "wrong-interpreter" else Path(sys.executable)
            )
            if state != "missing-interpreter":
                (target / "bin/python").symlink_to(interpreter)
    before = snapshot(inputs.root)
    result = invoke(inputs)
    expected = (
        0
        if state in {"empty", "matching"}
        else 3
        if state in {"file", "nonempty", "missing-interpreter"}
        else 2
    )
    assert result.returncode == expected, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["exit_code"] == expected
    assert snapshot(inputs.root) == before


@pytest.mark.parametrize(
    "tokens",
    [["--unknown", "private-sentinel"], ["--root"], ["--max-input-bytes", "private-sentinel"]],
)
def test_invalid_public_arguments_do_not_echo_values(
    inputs: EnvironmentInputs, tokens: list[str]
) -> None:
    """Native CLI parsing emits fixed invalid reports without received-value echo."""
    before = snapshot(inputs.root)
    result = invoke(inputs, *tokens)
    assert result.returncode == 4, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["status"] == "invalid"
    assert b"private-sentinel" not in result.stdout + result.stderr
    assert snapshot(inputs.root) == before


def test_boolean_api_budget_refuses(inputs: EnvironmentInputs) -> None:
    """A bool cannot become a one-byte caller budget through integer coercion."""
    with pytest.raises(Fault) as raised:
        verify(
            inputs.root,
            inputs.artifacts,
            inputs.owner,
            str(inputs.environment),
            max_input_bytes=True,
        )
    assert raised.value.exit_code == 4


def test_actual_unsupported_interpreter_refuses_before_any_write(inputs: EnvironmentInputs) -> None:
    """The pinned genuine unsupported interpreter refuses before bootstrap writes.

    It runs from its guard environment, the same pinned binary with the measurement installed.
    """
    assert hashlib.sha256(UNSUPPORTED_PYTHON.read_bytes()).hexdigest() == (
        "bb4d05c1f88e8568985e8704afe1822e82700a54bad9317c05c8eb96d3186701"
    )
    assert UNSUPPORTED_ENVIRONMENT.resolve() == UNSUPPORTED_PYTHON.resolve()
    before = snapshot(inputs.root)
    result = invoke(inputs, python=str(UNSUPPORTED_ENVIRONMENT))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert (
        json.loads(result.stdout)["reasons"][0]["code"] == "dependency_alignment.incompatible-patch"
    )
    assert snapshot(inputs.root) == before


@pytest.mark.parametrize("name", ["--owner-source", "--artifacts"])
def test_missing_operator_root_refuses_without_writes(inputs: EnvironmentInputs, name: str) -> None:
    """Empty required data roots remain unavailable rather than inferred."""
    before = snapshot(inputs.root)
    result = invoke(inputs, name, "")
    assert result.returncode == 3, (result.stdout, result.stderr)
    report = json.loads(result.stdout)
    assert report["reasons"][0]["code"] == "input_unavailable"
    assert snapshot(inputs.root) == before


def test_changed_actual_owner_source_refuses_without_writes(inputs: EnvironmentInputs) -> None:
    """A corrupted derivative of the genuine selected owner tree fails its binding."""
    owner = inputs.root / "owner-derivative"
    manifest = json.loads((inputs.artifacts / "owner-source-inputs.json").read_bytes())
    for item in manifest["files"]:
        target = owner / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        os.link(inputs.owner / item["path"], target)
    first = manifest["files"][0]
    original = inputs.owner / first["path"]
    damaged = owner / first["path"]
    damaged.unlink()
    damaged.write_bytes(b"Changed actual owner input.\n")
    selected = EnvironmentInputs(inputs.root, inputs.artifacts, owner, inputs.environment)
    before = snapshot(inputs.root)
    result = invoke(selected)
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert json.loads(result.stdout)["reasons"][0]["code"] == "source_identity_mismatch"
    assert hashlib.sha256(original.read_bytes()).hexdigest() == first["sha256"]
    assert snapshot(inputs.root) == before


def test_actual_prepare_uv_extracts_and_retains_the_selected_native_producer(
    inputs: EnvironmentInputs,
) -> None:
    """Real preparation uses admitted original bytes without creating an environment."""
    before = snapshot(inputs.root)
    command = [
        "make",
        "--no-print-directory",
        "prepare-uv",
        "BASE_PYTHON=" + sys.executable,
        "ENVIRONMENT_INPUTS=" + str(inputs.artifacts),
        "ENVIRONMENT_OWNER_SOURCE=" + str(inputs.owner),
    ]
    first = subprocess.run(command, cwd=inputs.root, capture_output=True, timeout=30)
    assert first.returncode == 0, (first.stdout, first.stderr)
    executable = inputs.root / ".tool-cache/bootstrap-uv/uv"
    assert hashlib.sha256(executable.read_bytes()).hexdigest() == (
        "4b5e59bc557ff2cd70934beb59d0eaa92820702853d49f0066b50aa11a8f0c52"
    )
    version = subprocess.run([str(executable), "--version"], capture_output=True, timeout=10)
    assert version.returncode == 0, (version.stdout, version.stderr)
    assert version.stdout.startswith(b"uv 0.13.7")
    assert not inputs.environment.exists()
    after = snapshot(inputs.root)
    assert all(after[name] == value for name, value in before.items())
    assert set(after) - set(before) == {
        ".tool-cache",
        ".tool-cache/bootstrap-uv",
        ".tool-cache/bootstrap-uv/uv",
    }
    state = executable.stat()
    second = subprocess.run(command, cwd=inputs.root, capture_output=True, timeout=30)
    assert second.returncode == 0, (second.stdout, second.stderr)
    retained = executable.stat()
    assert (retained.st_ino, retained.st_mtime_ns) == (state.st_ino, state.st_mtime_ns)
    assert snapshot(inputs.root) == after
