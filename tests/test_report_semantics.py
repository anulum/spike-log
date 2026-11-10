# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise the public closed transport schema and actual emission boundaries."""

import copy
import importlib
import json
import subprocess
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from local_scaffold.reports import Fault, safe_location, validate_child
from tests.conftest import SOURCE, source_python
from tests.test_preflight import ROLES


def independent_wire(gate: str = "repository_metadata") -> dict[str, Json]:
    """Create a transport fixture independently of production serialisation."""
    return {
        "report_schema": "spike_log.local-scaffold-guard-report.v1",
        "gate": gate,
        "scope": "local_scaffold",
        "status": "passed",
        "exit_code": 0,
        "reasons": [],
        "checks": [],
    }


@pytest.mark.parametrize("value", [None, [], "text", {}, True])
def test_non_report_shapes(value: object) -> None:
    """Transport shape is mandatory even for a successful native child."""
    with pytest.raises(Fault):
        validate_child(value, "repository_metadata", 0)


@pytest.mark.parametrize(
    "case",
    [
        "schema",
        "gate",
        "scope",
        "boolean-exit",
        "unknown-exit",
        "status",
        "reasons-shape",
        "excess-reasons",
        "checks-shape",
        "reason-shape",
        "reason-code-type",
        "reason-code",
        "reason-detail",
        "reason-location-type",
        "reason-location-absolute",
        "reason-location-control",
        "success-reasons",
        "failure-empty",
        "leaf-checks",
    ],
)
def test_report_semantic_refusals(case: str) -> None:
    """Closed values, safe locations and native semantic agreement are enforced."""
    value = independent_wire()
    native = 0
    reason: dict[str, Json] = {
        "code": "policy_refusal",
        "location": None,
        "detail": "Required local infrastructure condition failed: policy_refusal.",
    }
    if case in (
        "schema",
        "gate",
        "scope",
        "boolean-exit",
        "unknown-exit",
        "status",
        "reasons-shape",
        "checks-shape",
    ):
        replacements: dict[str, tuple[str, Json]] = {
            "schema": ("report_schema", "unknown"),
            "gate": ("gate", "preflight"),
            "scope": ("scope", "runtime"),
            "boolean-exit": ("exit_code", True),
            "unknown-exit": ("exit_code", 1),
            "status": ("status", "unavailable"),
            "reasons-shape": ("reasons", {}),
            "checks-shape": ("checks", False),
        }
        key, replacement = replacements[case]
        value[key] = replacement
    elif case == "excess-reasons":
        value["reasons"] = [dict(reason) for _ in range(257)]
    elif case == "failure-empty":
        value.update(exit_code=2, status="refused")
        native = 2
    elif case == "leaf-checks":
        value["checks"] = [{}]
    elif case == "success-reasons":
        value["reasons"] = [reason]
    else:
        value.update(exit_code=2, status="refused")
        native = 2
        if case == "reason-shape":
            value["reasons"] = [{}]
        else:
            if case == "reason-code-type":
                reason["code"] = []
            elif case == "reason-code":
                reason["code"] = "unknown"
            elif case == "reason-detail":
                reason["detail"] = "private-sentinel"
            elif case == "reason-location-type":
                reason["location"] = True
            elif case == "reason-location-absolute":
                reason["location"] = "/outside/private-sentinel"
            else:
                reason["location"] = "escaped\x1b"
            value["reasons"] = [reason]
    with pytest.raises(Fault):
        validate_child(value, "repository_metadata", native)


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "shape",
        "role",
        "codes-shape",
        "codes-nonstring",
        "codes-unknown",
        "codes-excess",
        "notrun-exit",
        "notrun-codes",
        "invalid-exit",
        "state-conflict",
        "empty-refusal",
        "aggregate-conflict",
    ],
)
def test_complete_preflight_semantics(case: str) -> None:
    """All eighteen roles and non-success states have exact aggregate semantics."""
    value = independent_wire("preflight")
    checks: list[Json] = [
        {"role": name, "status": "passed", "exit_code": 0, "reason_codes": []} for name in ROLES
    ]
    value["checks"] = checks
    validate_child(copy.deepcopy(value), "preflight", 0)
    check = cast(dict[str, Json], checks[0])
    if case == "missing":
        checks.pop()
    elif case == "shape":
        checks[0] = {}
    elif case == "role":
        check["role"] = "unknown"
    elif case == "codes-shape":
        check["reason_codes"] = {}
    elif case == "codes-nonstring":
        check["reason_codes"] = [{}]
    elif case == "codes-unknown":
        check["reason_codes"] = ["unknown"]
    elif case == "codes-excess":
        check["reason_codes"] = ["policy_refusal"] * 257
    elif case == "notrun-exit":
        check.update(status="not_run", exit_code=0, reason_codes=["required_not_run"])
    elif case == "notrun-codes":
        check.update(status="not_run", exit_code=None, reason_codes=[])
    elif case == "invalid-exit":
        check["exit_code"] = True
    elif case == "state-conflict":
        check["status"] = "refused"
    elif case == "empty-refusal":
        check.update(status="refused", exit_code=2)
    else:
        check.update(status="not_run", exit_code=None, reason_codes=["required_not_run"])
    with pytest.raises(Fault):
        validate_child(value, "preflight", 0)


@pytest.mark.parametrize(
    "location",
    ["", "../outside", "/absolute", "windows\\path", "control\x1b", "surrogate\ud800", "x" * 1025],
)
def test_safe_location_refusal(location: str) -> None:
    """Untrusted lexical paths cannot inject or disclose diagnostic locations."""
    assert safe_location(location) is None
    assert safe_location("docs/valid.md") == "docs/valid.md"


def test_native_report_emission_and_imports() -> None:
    """Actual text output and importable public wrappers retain the real contract."""
    for name in (
        "check_repository_metadata",
        "check_source_provenance",
        "check_workflow_policy",
        "check_dependency_alignment",
        "check_documentation",
        "check_repository_inventory",
        "preflight",
    ):
        importlib.import_module(name)
    code = "import sys;sys.path.insert(0,sys.argv[1]);from local_scaffold.reports import Report;r=Report('repository_metadata');r.add('policy_refusal');sys.exit(r.emit(False))"
    result = subprocess.run(
        source_python("-c", code, str(SOURCE / "tools")), capture_output=True, check=False
    )
    assert result.returncode == 2
    assert b"repository_metadata: refused" in result.stdout
    code = (
        "import sys;sys.path.insert(0,sys.argv[1]);"
        "from local_scaffold.reports import Report,validate_child;"
        "r=Report('preflight');code='dependency_alignment.common.duplicate-json-or-yaml';"
        "[r.add(code,'/'.join(['a'*200]*5)+str(i)) for i in range(255)];"
        f"r.checks=[dict(role=n,status='refused',exit_code=2,reason_codes=[code]*256) for n in {ROLES!r}];"
        "validate_child(r.payload(),'preflight',2);sys.exit(r.emit(True))"
    )
    result = subprocess.run(
        source_python("-c", code, str(SOURCE / "tools")), capture_output=True, check=False
    )
    assert result.returncode == 2
    assert not result.stdout
    assert b"output_failure" in result.stderr


@pytest.mark.parametrize("close_stderr", [False, True])
def test_actual_closed_output_objects(close_stderr: bool) -> None:
    """Genuinely closed text streams retain native2 without a second emission failure."""
    program = "import sys;sys.path.insert(0,sys.argv[1]);from local_scaffold.reports import Report;sys.stdout.close();"
    if close_stderr:
        program += "sys.stderr.close();"
    program += "sys.exit(Report('repository_metadata').emit(True))"
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools")), capture_output=True, check=False
    )
    assert result.returncode == 2
    assert not result.stdout
    if close_stderr:
        assert not result.stderr
    else:
        assert b"output_failure" in result.stderr


def test_actual_full_diagnostic_buffer_keeps_terminal_exit() -> None:
    """The real public report API keeps severity when no more reasons fit."""
    program = """import sys
sys.path.insert(0,sys.argv[1])
from local_scaffold.cli import retain_fault
from local_scaffold.reports import DiagnosticLimit,Fault,Report
report=Report('repository_metadata')
try:
    for _ in range(256):
        report.add('policy_refusal')
except DiagnosticLimit:
    pass
retain_fault(report,Fault('tool_unavailable',exit_code=3))
sys.exit(report.emit(True))
"""
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools")),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 3 and not result.stderr
    report = validate_child(json.loads(result.stdout), "repository_metadata", result.returncode)
    assert report["status"] == "unavailable" and len(report["reasons"]) == 256
    assert report["reasons"][-1]["code"] == "diagnostic_budget_exceeded"


@pytest.mark.parametrize(
    ("counts", "exits", "expected_exit", "executed"),
    [
        ((255,), (2,), 2, 18),
        ((256,), (2,), 3, 1),
        ((200, 56), (2, 2), 3, 2),
        ((200, 56), (2, 4), 4, 2),
        ((255, *([0] * 16), 1), (2, *([0] * 16), 2), 2, 18),
    ],
    ids=[
        "below-limit",
        "first-role-limit",
        "partial-budget",
        "invalid-precedence",
        "last-role-limit",
    ],
)
def test_actual_preflight_diagnostic_exhaustion_keeps_observed_roles(
    tmp_path: Path,
    counts: tuple[int, ...],
    exits: tuple[int, ...],
    expected_exit: int,
    executed: int,
) -> None:
    """Retain native child outcomes through the public finite-plan and report APIs.

    Parameters
    ----------
    tmp_path : Path
        Owned working directory containing each actually executed child's marker.
    counts : tuple[int, ...]
        Independent finite child diagnostic counts; later children succeed.
    exits : tuple[int, ...]
        Actual native exits for the corresponding finite child transports.
    expected_exit : int
        Complete parent precedence including genuinely unexecuted roles.
    executed : int
        Exact expected number of native child execution markers.
    """
    child = """import json,pathlib,sys
pathlib.Path(sys.argv[1]).write_text(sys.argv[3])
count,code=int(sys.argv[2]),int(sys.argv[3])
reason={'code':'policy_refusal','location':None,'detail':'Required local infrastructure condition failed: policy_refusal.'}
value={'report_schema':'spike_log.local-scaffold-guard-report.v1','gate':'repository_metadata','scope':'local_scaffold','status':{0:'passed',2:'refused',4:'invalid'}[code],'exit_code':code,'reasons':[dict(reason) for _ in range(count)],'checks':[]}
print(json.dumps(value))
sys.exit(code)
"""
    program = """import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold import orchestration
from local_scaffold.policy import ROLES
from local_scaffold.reports import Report
counts,exits=json.loads(sys.argv[3]),json.loads(sys.argv[4])
roles=tuple(orchestration.Role(name,(sys.executable,'-I','-c',sys.argv[5],str(Path(sys.argv[2])/name),str(counts[i] if i<len(counts) else 0),str(exits[i] if i<len(exits) else 0)),'repository_metadata') for i,name in enumerate(ROLES))
report=Report('preflight')
orchestration.run_plan(Path(sys.argv[2]),report,roles)
sys.exit(report.emit(True))
"""
    result = subprocess.run(
        source_python(
            "-I",
            "-c",
            program,
            str(SOURCE / "tools"),
            str(tmp_path),
            json.dumps(counts),
            json.dumps(exits),
            child,
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == expected_exit and not result.stderr, (result.stdout, result.stderr)
    value = validate_child(json.loads(result.stdout), "preflight", result.returncode)
    assert len(value["reasons"]) == min(sum(counts), 256)
    if sum(counts) >= 256:
        assert value["reasons"][-1]["code"] == "diagnostic_budget_exceeded"
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(ROLES[:executed])
    for i, check in enumerate(value["checks"]):
        if i < executed:
            code = exits[i] if i < len(exits) else 0
            count = counts[i] if i < len(counts) else 0
            assert check["exit_code"] == code
            assert check["status"] == {0: "passed", 2: "refused", 4: "invalid"}[code]
            assert check["reason_codes"] == ["policy_refusal"] * count
            assert (tmp_path / check["role"]).read_text() == str(code)
        else:
            assert check == {
                "role": ROLES[i],
                "status": "not_run",
                "exit_code": None,
                "reason_codes": ["required_not_run"],
            }


def test_complete_prerequisite_not_run_report() -> None:
    """A complete prerequisite refusal preserves every genuinely unexecuted role."""
    value = independent_wire("preflight")
    value.update(
        exit_code=2,
        status="refused",
        reasons=[
            {
                "code": "policy_refusal",
                "location": None,
                "detail": "Required local infrastructure condition failed: policy_refusal.",
            }
        ],
        checks=[
            {
                "role": role,
                "status": "not_run",
                "exit_code": None,
                "reason_codes": ["required_not_run"],
            }
            for role in ROLES
        ],
    )
    admitted = validate_child(value, "preflight", 2)
    assert admitted["exit_code"] == 2
    assert len(admitted["checks"]) == 18
    assert all(check["status"] == "not_run" for check in admitted["checks"])
