# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise whole dependency alignment through actual installed producers."""

import json
import re
from pathlib import Path

import pytest

from tests.conftest import payload, run_guard, snapshots


@pytest.mark.parametrize(
    "case",
    [
        "hook-version",
        "hook-language",
        "hook-extra",
        "hook-entry",
        "hook-repo",
        "hook-shape",
        "lock-hash",
        "lock-package",
        "lock-duplicate",
        "domain-package",
        "typing",
        "licence",
        "producer",
        "mutable-url",
        "source-hash",
        "direct-role",
        "direct-version",
        "audit-drift",
        "audit-absent",
    ],
)
def test_actual_dependency_refusals(root: Path, case: str) -> None:
    """Alter independently selected real inputs and retain producer mismatches."""
    if case.startswith("hook-"):
        path = root / ".pre-commit-config.yaml"
        text = path.read_text()
        if case == "hook-version":
            text = text.replace("python3.13", "python3.14")
        elif case == "hook-language":
            text = text.replace("language: system", "language: python")
        elif case == "hook-extra":
            text = text.replace(
                "language: system", "language: system\n      additional_dependencies: [rogue]"
            )
        elif case == "hook-entry":
            text = text.replace(".venv/bin/python ", "unknown ")
        elif case == "hook-repo":
            text = text.replace("repo: local", "repo: external")
        else:
            text = "repos: []\n"
        path.write_text(text)
    elif case.startswith("lock-"):
        path = root / "requirements-dev.txt"
        text = path.read_text()
        if case == "lock-hash":
            text = re.sub(r"--hash=sha256:[a-f0-9]{64}", "--hash=sha256:bad", text, count=1)
        elif case == "lock-package":
            text = text.replace("execnet==2.1.2", "execnet==0")
        else:
            text += "\nexecnet==2.1.2 --hash=sha256:" + "0" * 64 + "\n"
        path.write_text(text)
    elif case in ("domain-package", "typing"):
        path = root / "pyproject.toml"
        text = path.read_text()
        path.write_text(
            text.replace('name = "spike-log"', 'name = "dormant"')
            if case == "domain-package"
            else text.replace("strict = true", "strict = false")
        )
    elif case == "audit-drift":
        (root / ".tool-cache/security/pip-audit.json").write_text(
            '{"dependencies":[],"fixes":[]}\n'
        )
    elif case == "audit-absent":
        (root / ".tool-cache/security/pip-audit.json").unlink()
    elif case in ("direct-role", "direct-version"):
        path = root / "requirements-dev.in"
        text = path.read_text()
        path.write_text(
            text.replace("ruff==0.16.10", "ruff==0")
            if case == "direct-version"
            else text + "execnet==2.1.2\n"
        )
    else:
        import json

        path = root / "dependency-provenance.json"
        data = json.loads(path.read_bytes())
        record = data["packages"][0]
        if case == "licence":
            record["license_expression"] = "false owner AGPL"
        elif case == "producer":
            record["metadata_sha256"] = "0" * 64
        elif case == "mutable-url":
            record["source_artifact"]["url"] = "https://example.invalid/latest"
        else:
            record["source_artifact"]["sha256"] = "0" * 64
        path.write_text(json.dumps(data) + "\n")
    payload(run_guard("dependency_alignment", root), 3 if case == "audit-absent" else 2)


def test_complete_dependency_graph(root: Path) -> None:
    """Run the real entire graph twice with immutable inputs and audit bytes."""
    before = snapshots(root)
    a = run_guard("dependency_alignment", root)
    b = run_guard("dependency_alignment", root)
    payload(a, 0)
    assert a.stdout == b.stdout
    assert snapshots(root) == before


@pytest.mark.parametrize("stamp", ["2000-01-01T00:00:00+00:00", "2999-01-01T00:00:00+00:00"])
def test_received_audit_stamp_cannot_create_freshness(root: Path, stamp: str) -> None:
    """Real old/future input cannot replace the independently admitted producer time."""
    value = json.loads((root / "dependency-provenance.json").read_text())
    value["security_audit"]["produced_at"] = stamp
    (root / "dependency-provenance.json").write_text(json.dumps(value))
    record = payload(run_guard("dependency_alignment", root), 2)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(r, dict) and r.get("code") == "source_identity_mismatch" for r in reasons)


@pytest.mark.parametrize("stamp", ["invalid", "2026-10-02T12:00:00", 7])
def test_audit_stamp_must_be_aware_native_time(root: Path, stamp: str | int) -> None:
    """Malformed or timezone-free audit stamps remain invalid real inputs."""
    value = json.loads((root / "dependency-provenance.json").read_text())
    value["security_audit"]["produced_at"] = stamp
    (root / "dependency-provenance.json").write_text(json.dumps(value))
    payload(run_guard("dependency_alignment", root), 4)


@pytest.mark.parametrize("snapshot", [None, {}, [], {"producer": "pip-audit"}])
def test_complete_audit_stamp_required(root: Path, snapshot: object) -> None:
    """Received incomplete producer provenance cannot hide a required audit role."""
    value = json.loads((root / "dependency-provenance.json").read_text())
    value["security_audit"] = snapshot
    (root / "dependency-provenance.json").write_text(json.dumps(value))
    payload(run_guard("dependency_alignment", root), 4)


@pytest.mark.parametrize(
    "case", ["shape", "dependency", "name", "version", "duplicate", "vulnerable", "fixes"]
)
def test_real_changed_audit_semantics_remain_refused(root: Path, case: str) -> None:
    """Unadmitted audit bytes retain producer drift and their actual semantic fault."""
    path = root / ".tool-cache/security/pip-audit.json"
    value = json.loads(path.read_text())
    if case == "shape":
        value["dependencies"] = None
    elif case == "dependency":
        value["dependencies"].append({})
    elif case in {"name", "version"}:
        value["dependencies"][0][case] = 7
    elif case == "duplicate":
        value["dependencies"].append(value["dependencies"][0])
    elif case == "vulnerable":
        value["dependencies"][0]["vulns"] = [{"id": "independent-fixture-finding"}]
    else:
        value["fixes"] = ["unadmitted-fix"]
    path.write_text(json.dumps(value))
    record = payload(run_guard("dependency_alignment", root), 4 if case == "shape" else 2)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(r, dict) and r.get("code") == "source_identity_mismatch" for r in reasons)


@pytest.mark.parametrize(
    ("case", "exit_code", "reason"),
    [
        ("packages-shape", 4, "configuration_invalid"),
        ("record-shape", 4, "configuration_invalid"),
        ("name-type", 4, "configuration_invalid"),
        ("name-empty", 4, "configuration_invalid"),
        ("name-invalid", 4, "configuration_invalid"),
        ("artifact-shape", 2, "dependency_alignment.mutable-download"),
        ("artifact-url-type", 2, "dependency_alignment.mutable-download"),
    ],
)
def test_actual_provenance_field_boundaries(
    root: Path, case: str, exit_code: int, reason: str
) -> None:
    """Malformed full producer records retain authored closed configuration refusals."""
    path = root / "dependency-provenance.json"
    value = json.loads(path.read_bytes())
    if case == "packages-shape":
        value["packages"] = {}
    elif case == "record-shape":
        value["packages"][0] = "invalid record"
    elif case == "name-type":
        value["packages"][0]["name"] = 7
    elif case == "name-empty":
        value["packages"][0]["name"] = ""
    elif case == "name-invalid":
        value["packages"][0]["name"] = "package with spaces"
    elif case == "artifact-shape":
        value["packages"][0]["source_artifact"] = None
    else:
        value["packages"][0]["source_artifact"]["url"] = 7
    path.write_text(json.dumps(value) + "\n")
    record = payload(run_guard("dependency_alignment", root), exit_code)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(item, dict) and item["code"] == reason for item in reasons)
    assert all(not isinstance(item, dict) or item["code"] != "unexpected_fault" for item in reasons)


TOML_CONTAINER_INPUTS = {
    "tool-string": "tool='private-sentinel'\n",
    "tool-array": "tool=[]\n",
    "tool-boolean": "tool=false\n",
    "mypy-string": "[tool]\nmypy='private-sentinel'\n",
    "mypy-array": "[tool]\nmypy=[]\n",
    "mypy-boolean": "[tool]\nmypy=true\n",
}


@pytest.mark.parametrize(
    "case",
    ["typing-toml", "repository-entry", "hook-list", "hook-entry-shape", *TOML_CONTAINER_INPUTS],
)
def test_actual_hook_and_typing_shapes(root: Path, case: str) -> None:
    """Actual syntax and YAML container faults refuse without executing configuration."""
    if case == "typing-toml":
        (root / "pyproject.toml").write_text("[invalid TOML\n")
        expected = 4
    elif case in TOML_CONTAINER_INPUTS:
        (root / "pyproject.toml").write_text(TOML_CONTAINER_INPUTS[case])
        expected = 2
    else:
        path = root / ".pre-commit-config.yaml"
        if case == "repository-entry":
            path.write_text("repos: [7]\n")
        elif case == "hook-list":
            path.write_text("repos:\n  - repo: local\n    hooks: null\n")
        else:
            path.write_text("repos:\n  - repo: local\n    hooks: [7]\n")
        expected = 2
    before = snapshots(root)
    result = run_guard("dependency_alignment", root)
    record = payload(result, expected)
    assert snapshots(root) == before
    assert b"private-sentinel" not in result.stdout
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(item, dict)
        and item["code"]
        == ("configuration_invalid" if expected == 4 else "dependency_alignment.hook-drift")
        for item in reasons
    )
    assert all(not isinstance(item, dict) or item["code"] != "unexpected_fault" for item in reasons)


@pytest.mark.parametrize("case", ["builder", "dependency", "private-include", "extra-source"])
def test_only_reviewed_native_package_is_a_dependency_input(root: Path, case: str) -> None:
    """Reject real unreviewed package changes through the dependency command."""
    config = root / "pyproject.toml"
    text = config.read_text()
    if case == "builder":
        config.write_text(text.replace("poetry-core==2.5.0", "poetry-core==2.4.0"))
    elif case == "dependency":
        config.write_text(text.replace("evidence-manifest-toolkit==0.0.0.dev0", "unreviewed==1", 1))
    elif case == "private-include":
        config.write_text(text.replace('path = "src/spike_log/py.typed"', 'path = "docs/internal"'))
    else:
        (root / "src/spike_log/unreviewed.py").write_text('"""Unreviewed received input."""\n')
    before = snapshots(root)
    record = payload(run_guard("dependency_alignment", root), 2)
    assert snapshots(root) == before
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "dependency_alignment.runtime-dep"
        for reason in reasons
    )
