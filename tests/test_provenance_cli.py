# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise the actual provenance command and public Python entry point."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, payload, run_guard, source_python
from tests.test_provenance_local import INPUTS, OWNER
from tests.test_provenance_reproduction import invoke, reproduction_root, source_cohort

__all__ = ["reproduction_root", "source_cohort"]


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["--inputs", ""],
        ["--inputs", ".", "--inputs", "."],
        ["--inputs", ".", "--mode", "unknown"],
        ["--inputs", ".", "--mode", "generate"],
        ["--inputs", ".", "--output", "candidate.json"],
        ["--inputs", ".", "--mode", "generate", "--output", "candidate.json", "--reference", "x"],
        ["--inputs", ".", "--unknown-option"],
        ["--inputs", ".", "--artifacts", ""],
        ["--inputs", ".", "--owner-source", ""],
        ["--inputs", ".", "--artifacts", ".", "--artifacts", "."],
        ["--inputs", ".", "--owner-source", ".", "--owner-source", "."],
        ["--inputs", ".", "--mode", "capture", "--output", "candidate.json"],
        ["--inputs", ".", "--mode", "capture", "--reference", "candidate.json"],
        ["--inputs", ".", "--roo", "absent-root"],
        ["--inp", ".", "--root", "absent-root"],
        ["--inputs", ".", "--mo", "verify", "--root", "absent-root"],
        ["--inputs", ".", "--ref", "dependency-provenance.json", "--root", "absent-root"],
        [
            "--inputs",
            ".",
            "--mode",
            "generate",
            "--out",
            "candidate.json",
            "--root",
            "absent-root",
        ],
    ],
)
def test_invalid_cli_options(arguments: list[str]) -> None:
    """Unsupported options report invalid invocation through the real process."""
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/reproduce_dependency_provenance.py"), "--json", *arguments
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=10,
    )
    assert payload(result, 4)["status"] == "invalid"


def test_public_function_invalid_invocation() -> None:
    """The public Python entry point preserves maintained invocation behavior."""
    from reproduce_dependency_provenance import main

    assert main(["--json"]) == 4


@pytest.mark.parametrize(
    "filename",
    [
        "check_repository_metadata.py",
        "check_source_provenance.py",
        "check_workflow_policy.py",
        "check_dependency_alignment.py",
        "check_documentation.py",
        "check_repository_inventory.py",
        "preflight.py",
        "reproduce_dependency_provenance.py",
    ],
)
@pytest.mark.parametrize("help_option", ["-h", "--help"])
@pytest.mark.parametrize("json_requested", [False, True])
def test_cli_help(tmp_path: Path, filename: str, help_option: str, json_requested: bool) -> None:
    """Every public help is informational text, even when JSON was requested."""
    absent = tmp_path / "absent-repository"
    arguments = ["--root", str(absent)]
    if json_requested:
        arguments.append("--json")
    result = subprocess.run(
        source_python(str(SOURCE / "tools" / filename), *arguments, help_option),
        cwd=SOURCE,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0 and not result.stderr
    assert result.stdout.startswith(b"usage:")
    assert b"--root" in result.stdout and b"--json" in result.stdout
    assert b'"report_schema"' not in result.stdout
    assert not absent.exists()
    assert not list(tmp_path.iterdir())
    if filename == "reproduce_dependency_provenance.py":
        assert b"--inputs" in result.stdout and b"--reference" in result.stdout


def test_inventory_requires_public_provenance_entry(root: Path, tmp_path: Path) -> None:
    """A complete real tree passes and its absent public command is unavailable."""
    payload(run_guard("repository_inventory", root, "--mode", "verify"), 0)
    name = "tools/reproduce_dependency_provenance.py"
    entry = root / name
    before = entry.read_bytes()
    retained = tmp_path / "retained-provenance-entry.py"
    entry.rename(retained)
    result = payload(run_guard("repository_inventory", root, "--mode", "verify"), 3)
    assert any(row["location"] == name for row in cast(list[dict[str, Json]], result["reasons"]))
    assert retained.read_bytes() == before
    assert (SOURCE / name).read_bytes() == before
    assert not entry.exists()


@pytest.mark.parametrize("mode", ["capture", "generate"])
def test_public_api_unencodable_root(mode: str) -> None:
    """Both public Python modes contain a genuine unencodable filesystem argument."""
    program = (
        "import sys;sys.path.insert(0," + repr(str(SOURCE / "tools")) + ");"
        "from reproduce_dependency_provenance import main;"
        "arguments=['--root',chr(0xD800),'--inputs','.','--mode',sys.argv[1],'--json'];"
        "\nif sys.argv[1]=='generate': arguments.extend(['--output','candidate.json'])"
        "\nraise SystemExit(main(arguments))"
    )
    result = payload(
        subprocess.run(
            source_python("-c", program, mode), cwd=SOURCE, capture_output=True, timeout=30
        ),
        2,
    )
    assert [row["code"] for row in cast(list[dict[str, Json]], result["reasons"])] == [
        "unexpected_fault"
    ]


def test_public_capture_user_interruption(reproduction_root: Path) -> None:
    """The actual public capture API completes owned cleanup after user interruption."""
    program = (
        "import sys,threading,os,signal;"
        "sys.path.insert(0," + repr(str(SOURCE / "tools")) + ");"
        "from reproduce_dependency_provenance import main;"
        "timer=threading.Timer(0.25,os.kill,args=(os.getpid(),signal.SIGINT));timer.start();"
        "\ntry: result=main(['--root',sys.argv[1],'--inputs','.tool-cache/inputs',"
        "'--mode','capture','--json'])"
        "\nfinally: timer.cancel();timer.join()"
        "\nraise SystemExit(result)"
    )
    result = payload(
        subprocess.run(
            source_python("-c", program, str(reproduction_root)),
            cwd=SOURCE,
            capture_output=True,
            timeout=30,
        ),
        3,
    )
    assert [row["code"] for row in cast(list[dict[str, Json]], result["reasons"])] == [
        "interrupted"
    ]
    assert not (reproduction_root / ".tool-cache/inputs/inputs.json").exists()


@pytest.mark.parametrize("mode", ["capture", "generate"])
def test_public_bounded_diagnostics(
    reproduction_root: Path, source_cohort: Path, mode: str
) -> None:
    """The public CLI preserves the diagnostic ceiling before either writing operation."""
    path = reproduction_root / "repository-domain.json"
    metadata = json.loads(path.read_bytes())
    metadata["capabilities"] = ["ARCH" + "-CASE-" + str(i) for i in range(300)]
    path.write_text(json.dumps(metadata) + "\n")
    before = path.read_bytes()
    arguments = ["--mode", mode]
    if mode == "generate":
        arguments += ["--output", ".tool-cache/candidate.json"]
    inputs = source_cohort if mode == "generate" else Path(".tool-cache/inputs")
    result = payload(invoke(reproduction_root, inputs, *arguments), 2)
    reasons = cast(list[dict[str, Json]], result["reasons"])
    assert len(reasons) == 256 and reasons[-1]["code"] == "diagnostic_budget_exceeded"
    assert path.read_bytes() == before
    assert not (reproduction_root / ".tool-cache/inputs").exists()
    assert not (reproduction_root / ".tool-cache/candidate.json").exists()


def test_explicit_local_roots_keep_complete_registry_generation(
    reproduction_root: Path,
    source_cohort: Path,
) -> None:
    """Explicit data roots give the complete reconstruction, owner-source records included."""
    output = ".tool-cache/explicit-source-roots.json"
    response = payload(
        invoke(
            reproduction_root,
            source_cohort,
            "--mode",
            "generate",
            "--output",
            output,
            "--artifacts",
            str(INPUTS),
            "--owner-source",
            str(OWNER),
        ),
        0,
    )
    assert response["scope"] == "provenance_candidate"
    generated = json.loads((reproduction_root / output).read_bytes())
    baseline = json.loads((SOURCE / "dependency-provenance.json").read_bytes())["packages"]
    assert len(generated["packages"]) == len(baseline)
    assert {record["name"] for record in generated["packages"] if "source_kind" in record} == {
        "evidence-manifest-toolkit",
        "rfc8785",
    }
