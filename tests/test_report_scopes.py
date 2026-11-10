# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — existing operation report scopes and owning consumers

"""Exercise existing native operation reports through the public scoped consumer."""

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Literal

import pytest

from local_scaffold.reports import Fault, Report, validate_child
from tests.conftest import SOURCE, payload, source_python

type OperationScope = Literal[
    "local_scaffold",
    "inventory_generate",
    "audit_produce",
    "provenance_inputs",
    "provenance_candidate",
    "provenance_comparison",
]

SCOPES: tuple[tuple[str, OperationScope], ...] = (
    ("repository_metadata", "local_scaffold"),
    ("repository_inventory", "inventory_generate"),
    ("dependency_alignment", "audit_produce"),
    ("provenance_reproduction", "provenance_inputs"),
    ("provenance_reproduction", "provenance_candidate"),
    ("provenance_reproduction", "provenance_comparison"),
)
GATES = (
    "repository_metadata",
    "source_provenance",
    "workflow_policy",
    "dependency_alignment",
    "documentation",
    "repository_inventory",
    "preflight",
    "provenance_reproduction",
)


@pytest.mark.parametrize(("gate", "scope"), SCOPES)
@pytest.mark.parametrize("code", [0, 2, 3, 4])
def test_actual_native_scope_round_trip(gate: str, scope: OperationScope, code: int) -> None:
    """Admit each existing operation's native diagnostic outcome without mode inference."""
    program = """import sys
sys.path.insert(0,sys.argv[1])
from local_scaffold.reports import Report
gate,scope,code=sys.argv[2],sys.argv[3],int(sys.argv[4])
report=Report(gate,scope=scope)
if code:
    report.add({2:'policy_refusal',3:'tool_unavailable',4:'configuration_invalid'}[code],exit_code=code)
raise SystemExit(report.emit(True))
"""
    result = subprocess.run(
        source_python("-I", "-c", program, str(SOURCE / "tools"), gate, scope, str(code)),
        capture_output=True,
        timeout=20,
    )
    admitted = validate_child(payload(result, code), gate, code, expected_scope=scope)
    assert admitted["scope"] == scope and admitted["exit_code"] == code


@pytest.mark.parametrize(("gate", "scope"), SCOPES[1:])
def test_nondefault_scope_requires_explicit_consumer(gate: str, scope: OperationScope) -> None:
    """The unchanged default consumer does not select an operation from report data."""
    value = Report(gate, scope=scope).payload()
    with pytest.raises(Fault) as error:
        validate_child(value, gate, 0)
    assert error.value.code == "child_report_invalid"


@pytest.mark.parametrize(
    ("gate", "scope"),
    [(gate, scope) for owner, scope in SCOPES[1:] for gate in GATES if gate != owner],
)
def test_nondefault_scope_preserves_producer_ownership(gate: str, scope: OperationScope) -> None:
    """Known operations cannot be reassigned to another implemented report producer."""
    value = Report(gate, scope=scope).payload()
    with pytest.raises(Fault) as error:
        validate_child(value, gate, 0, expected_scope=scope)
    assert error.value.code == "child_report_invalid"


def test_actual_inventory_generation_report_is_consumable(tmp_path: Path) -> None:
    """A real successful generation CLI report reaches the explicit operation consumer."""
    token = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:20]
    name = ".tool-cache/report-scope-inventory-" + token + ".json"
    destination = SOURCE / name
    assert not destination.exists()
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/check_repository_inventory.py"),
            "--root",
            str(SOURCE),
            "--mode",
            "generate",
            "--output",
            name,
            "--json",
        ),
        capture_output=True,
        timeout=30,
    )
    admitted = validate_child(
        payload(result, 0), "repository_inventory", 0, expected_scope="inventory_generate"
    )
    assert admitted["scope"] == "inventory_generate"
    generated = json.loads(destination.read_bytes())
    assert generated["capabilities"] == []


@pytest.mark.parametrize(
    ("mode", "scope"),
    [
        ("capture", "provenance_inputs"),
        ("generate", "provenance_candidate"),
        ("verify", "provenance_comparison"),
    ],
)
def test_actual_provenance_mode_reports_preserve_scope(
    tmp_path: Path, mode: str, scope: OperationScope
) -> None:
    """Actual offline input unavailability remains a consumable mode-specific outcome."""
    arguments = [
        str(SOURCE / "tools/reproduce_dependency_provenance.py"),
        "--root",
        str(tmp_path / "absent-repository"),
        "--inputs",
        str(tmp_path / "absent-inputs"),
        "--mode",
        mode,
        "--json",
    ]
    if mode == "generate":
        arguments.extend(["--output", ".tool-cache/prospective.json"])
    result = subprocess.run(source_python(*arguments), capture_output=True, timeout=30)
    admitted = validate_child(
        payload(result, 3), "provenance_reproduction", 3, expected_scope=scope
    )
    assert admitted["scope"] == scope and admitted["reasons"][0]["code"] == "root_unavailable"
    assert not (tmp_path / "absent-repository").exists()


@pytest.mark.parametrize(("gate", "scope"), SCOPES)
def test_actual_native_exit_mismatch_remains_refused(gate: str, scope: OperationScope) -> None:
    """Every scope retains actual native/report agreement after operation selection."""
    program = """import sys
sys.path.insert(0,sys.argv[1])
from local_scaffold.reports import Report
report=Report(sys.argv[2],scope=sys.argv[3])
report.emit(True)
raise SystemExit(2)
"""
    result = subprocess.run(
        source_python("-I", "-c", program, str(SOURCE / "tools"), gate, scope),
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 2 and not result.stderr
    value = json.loads(result.stdout)
    assert value["exit_code"] == 0
    with pytest.raises(Fault) as error:
        validate_child(value, gate, result.returncode, expected_scope=scope)
    assert error.value.code == "child_status_mismatch"
