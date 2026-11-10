# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Qualify actual supplied outcomes through the fixed public workflow command."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, change, payload, run_guard, source_python

ROLES = ("pre-commit", "docs", "codeql", "security-audit", "sbom", "scorecard")
INPUT = "received-outcomes.json"
ADVERSE = "workflow_policy.aggregate-skipped"


def successful() -> dict[str, Json]:
    """Create an independent exact six-role positive input."""
    return dict.fromkeys(ROLES, "success")


def input_cases() -> list[tuple[str, Json, int, str | None]]:
    """Create every role/status pair and each independent closed-shape refusal."""
    cases: list[tuple[str, Json, int, str | None]] = [("all-six-success", successful(), 0, None)]
    for role in ROLES:
        for status in ("failure", "cancelled", "skipped", "not_run"):
            cases.append((role + "-" + status, successful() | {role: status}, 2, ADVERSE))
    cases.extend(
        [
            ("all-six-not-run", dict.fromkeys(ROLES, "not_run"), 2, ADVERSE),
            (
                "mixed-adverse",
                successful()
                | {
                    "docs": "failure",
                    "codeql": "cancelled",
                    "security-audit": "skipped",
                    "sbom": "not_run",
                },
                2,
                ADVERSE,
            ),
        ]
    )
    for role in ROLES:
        value = successful()
        value.pop(role)
        cases.append(("missing-" + role, value, 2, "policy_refusal"))
    invalid: list[tuple[str, Json]] = [
        ("extra-complete", successful() | {"complete": "success"}),
        ("extra-unknown", successful() | {"unknown": "success"}),
        ("empty-object", {}),
        ("array", []),
        ("null", None),
        ("scalar", "success"),
        ("nested-GitHub-result", successful() | {"docs": {"result": "success", "outputs": {}}}),
        ("boolean", successful() | {"docs": True}),
        ("number", successful() | {"docs": 0}),
        ("null-value", successful() | {"docs": None}),
        ("wrong-case", successful() | {"docs": "Success"}),
        ("unknown-status", successful() | {"docs": "pending"}),
        ("empty-status", successful() | {"docs": ""}),
    ]
    cases.extend((name, value, 2, "policy_refusal") for name, value in invalid)
    return cases


def pins(root: Path) -> dict[str, dict[str, Json]]:
    """Record actual bytes, inode and modification time of the fixed local inputs."""
    names = ["workflow-policy.json", INPUT]
    names.extend(
        ".github/workflows/" + name
        for name in (
            "ci.yml",
            "pre-commit.yml",
            "docs.yml",
            "codeql.yml",
            "security-audit.yml",
            "sbom.yml",
            "scorecard.yml",
        )
    )
    observed: dict[str, dict[str, Json]] = {}
    for name in names:
        path = root / name
        if not path.exists() or path.is_symlink():
            continue
        info = path.stat()
        if stat.S_ISREG(info.st_mode):
            try:
                raw = path.read_bytes()
                computed = hashlib.sha256(raw).hexdigest()
                digest: str | None = computed
                directory = SOURCE / ".tool-cache/received-outcome-inputs"
                assert not directory.is_symlink()
                directory.mkdir(exist_ok=True)
                retained = directory / (computed + ".bin")
                try:
                    with retained.open("xb") as stream:
                        stream.write(raw)
                except FileExistsError:
                    assert not retained.is_symlink() and retained.read_bytes() == raw
            except PermissionError:
                digest = None
            observed[name] = {
                "byte_length": info.st_size,
                "sha256": digest,
                "inode": info.st_ino,
                "mtime_ns": info.st_mtime_ns,
            }
    return observed


def observe(
    root: Path, case: str, expected: int, *arguments: str, gate: str = "workflow_policy"
) -> tuple[dict[str, Json], bytes]:
    """Retain real command receipts before asserting native/report/readonly agreement."""
    before = pins(root)
    result = run_guard(gate, root, *arguments)
    after = pins(root)
    directory = SOURCE / ".tool-cache/received-outcome-observations"
    assert not directory.is_symlink()
    directory.mkdir(exist_ok=True)
    record = {
        "case": case,
        "root": str(root),
        "argv": result.args,
        "native_exit": result.returncode,
        "stdout": result.stdout.decode(),
        "stderr": result.stderr.decode(),
        "before": before,
        "after": after,
        "reaped": True,
        "timed_out": False,
        "source_python": str(Path(sys.executable)),
    }
    with (directory / (uuid.uuid4().hex + ".json")).open("x") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.write("\n")
    value = payload(result, expected)
    assert value["gate"] == gate and value["scope"] == "local_scaffold"
    assert not value["checks"] if gate != "preflight" else True
    assert after == before
    return value, result.stdout


def reasons(value: dict[str, Json]) -> list[dict[str, Json]]:
    """Narrow the independently observed closed report reason objects."""
    rows = value["reasons"]
    assert isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
    return cast(list[dict[str, Json]], rows)


@pytest.mark.parametrize(
    "case,value,expected,reason",
    input_cases(),
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_received_input_shapes(
    root: Path, case: str, value: Json, expected: int, reason: str | None
) -> None:
    """The actual leaf returns native2 for every adverse role and invalid shape."""
    (root / INPUT).write_text(json.dumps(value) + "\n")
    report, _ = observe(root, case, expected, "--outcomes", INPUT)
    observed = reasons(report)
    if reason is None:
        assert not observed
    else:
        assert observed == [
            {
                "code": reason,
                "location": INPUT,
                "detail": "Required local infrastructure condition failed: " + reason + ".",
            }
        ]


@pytest.mark.parametrize("adverse", [False, True])
def test_static_graph_conjunction(root: Path, adverse: bool) -> None:
    """Supplied successes cannot erase graph faults, and both stages retain refusals."""
    (root / INPUT).write_text(json.dumps(successful() | ({"docs": "skipped"} if adverse else {})))
    change(root, "workflow-policy.json", ("platform",), "unsupported")
    report, _ = observe(
        root, "adverse-bad-graph" if adverse else "all-success-bad-graph", 2, "--outcomes", INPUT
    )
    observed = reasons(report)
    assert any(row["location"] == "workflow-policy.json" for row in observed)
    assert any(row["code"] == ADVERSE and row["location"] == INPUT for row in observed) == adverse


@pytest.mark.parametrize(
    "case,raw,reason",
    [
        ("duplicate-member", b'{"docs":"success","docs":"skipped"}', "duplicate_member"),
        ("malformed-json", b'{"docs":', "policy_refusal"),
        ("malformed-utf8", b'{"docs":"\xff"}', "input_encoding_invalid"),
        ("escaped-surrogate", b'{"docs":"\\ud800"}', "input_unicode_invalid"),
        ("nonfinite", b'{"docs":NaN}', "policy_refusal"),
        ("input-limit", b" " * 1048577, "resource_limit"),
        ("json-depth-limit", b"[" * 65 + b"0" + b"]" * 65, "resource_limit"),
        ("json-value-limit", b"[" + b"0," * 99999 + b"0]", "resource_limit"),
        ("json-string-limit", b'"' + b"a" * 65537 + b'"', "resource_limit"),
    ],
    ids=[
        "duplicate-member",
        "malformed-json",
        "malformed-utf8",
        "escaped-surrogate",
        "nonfinite",
        "input-limit",
        "json-depth-limit",
        "json-value-limit",
        "json-string-limit",
    ],
)
def test_actual_input_admission(root: Path, case: str, raw: bytes, reason: str) -> None:
    """Malformed bytes and exact resource excess are refused before shape validation."""
    (root / INPUT).write_bytes(raw)
    report, _ = observe(root, case, 2, "--outcomes", INPUT)
    assert [row["code"] for row in reasons(report)] == [reason]


@pytest.mark.parametrize(
    "case",
    [
        "absolute-path",
        "parent-escape",
        "symlink-file",
        "symlink-ancestor",
        "fifo",
        "path-limit",
        "unreadable-file",
    ],
)
def test_actual_filesystem_admission(root: Path, case: str) -> None:
    """Actual no-read, symlink and special-file cases have bounded native failures."""
    path = root / INPUT
    path.write_text(json.dumps(successful()))
    argument = INPUT
    expected = 2
    if case == "absolute-path":
        argument = str(path)
    elif case == "parent-escape":
        argument = "../outside.json"
    elif case == "symlink-file":
        path.unlink()
        path.symlink_to(root / "workflow-policy.json")
    elif case == "symlink-ancestor":
        (root / "linked").symlink_to(root, target_is_directory=True)
        argument = "linked/" + INPUT
    elif case == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif case == "path-limit":
        argument = "x" * 1025
    else:
        assert os.geteuid() != 0, "A privileged reader cannot qualify the unreadable-input case."
        path.chmod(0)
        expected = 3
    try:
        report, _ = observe(root, case, expected, "--outcomes", argument)
        if case == "unreadable-file":
            assert [row["code"] for row in reasons(report)] == ["input_unavailable"]
    finally:
        if case == "unreadable-file":
            path.chmod(0o600)


@pytest.mark.parametrize(
    "case,arguments",
    [
        ("missing-option-value", ["--outcomes"]),
        ("empty-option-value", ["--outcomes="]),
        ("empty-two-token", ["--outcomes", ""]),
        ("duplicate-option", ["--outcomes", INPUT, "--outcomes", INPUT]),
        ("duplicate-mixed-option", ["--outcomes=" + INPUT, "--outcomes", "conflicting.json"]),
        ("duplicate-equals-option", ["--outcomes=" + INPUT, "--outcomes=" + INPUT]),
        ("unknown-option", ["--outcomes", INPUT, "--unrecognized-private-value"]),
        ("abbreviated-option", ["--outcome", INPUT]),
        ("positional-input", [INPUT]),
        ("precedence-invalid-invocation", ["--unknown-private-value", "--outcomes", "absent.json"]),
    ],
)
def test_invalid_outcomes_invocations(root: Path, case: str, arguments: list[str]) -> None:
    """Both spellings reject repetitions and ambiguous calls without input access."""
    report, raw = observe(root, case, 4, *arguments)
    assert [row["code"] for row in reasons(report)] == ["invocation_invalid"]
    assert b"private-value" not in raw


@pytest.mark.parametrize(
    "gate",
    [
        "repository_metadata",
        "source_provenance",
        "dependency_alignment",
        "documentation",
        "repository_inventory",
        "preflight",
    ],
)
def test_outcomes_is_workflow_only(root: Path, gate: str) -> None:
    """Every other existing public guard rejects the optional workflow input."""
    report, _ = observe(root, "wrong-gate:" + gate, 4, "--outcomes", INPUT, gate=gate)
    assert [row["code"] for row in reasons(report)] == ["invocation_invalid"]


@pytest.mark.parametrize("bad_graph", [False, True])
def test_unavailable_outcomes_precedence(root: Path, bad_graph: bool) -> None:
    """Missing input3 retains a previously observed graph2 condition."""
    if bad_graph:
        change(root, "workflow-policy.json", ("platform",), "unsupported")
    report, _ = observe(
        root, "precedence-missing-input" if bad_graph else "missing-file", 3, "--outcomes", INPUT
    )
    observed = reasons(report)
    assert any(row["code"] == "input_unavailable" for row in observed)
    assert any(row["location"] == "workflow-policy.json" for row in observed) == bad_graph


def test_spelling_order_and_default_extent(root: Path) -> None:
    """Flag spellings, key order and repeated effective inputs have identical reports."""
    value = successful()
    (root / INPUT).write_text(json.dumps(value))
    _, first = observe(root, "option-equivalence:two-token", 0, "--outcomes", INPUT)
    _, equals = observe(root, "option-equivalence:equals", 0, "--outcomes=" + INPUT)
    assert equals == first
    (root / INPUT).write_text(json.dumps(dict(reversed(list(value.items()))), indent=2))
    _, reordered = observe(root, "shape-order-invariance", 0, "--outcomes", INPUT)
    assert reordered == first
    (root / INPUT).write_text(json.dumps(value | {"docs": "skipped"}))
    _, default = observe(root, "static-default-regression", 0)
    assert default == first


@pytest.mark.parametrize("adverse", [False, True])
def test_repeat_readonly_projection(root: Path, adverse: bool) -> None:
    """Actual graph and outcome bytes, inode and mtime survive repeated checks."""
    (root / INPUT).write_text(json.dumps(successful() | ({"docs": "not_run"} if adverse else {})))
    expected = 2 if adverse else 0
    case = "readonly-adverse" if adverse else "readonly-success"
    _, first = observe(root, case, expected, "--outcomes", INPUT)
    _, second = observe(root, case + ":repeat", expected, "--outcomes", INPUT)
    assert first == second


def test_received_outcomes_closed_stdout(root: Path) -> None:
    """A real closed output consumer cannot turn an admitted operation into success."""
    (root / INPUT).write_text(json.dumps(successful()))
    reader, writer = os.pipe()
    os.close(reader)
    before = pins(root)
    try:
        result = subprocess.run(
            source_python(
                str(SOURCE / "tools/check_workflow_policy.py"),
                "--root",
                str(root),
                "--outcomes",
                INPUT,
                "--json",
            ),
            cwd=SOURCE,
            stdout=writer,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    finally:
        os.close(writer)
    after = pins(root)
    directory = SOURCE / ".tool-cache/received-outcome-observations"
    assert not directory.is_symlink()
    directory.mkdir(exist_ok=True)
    with (directory / (uuid.uuid4().hex + ".json")).open("x") as stream:
        json.dump(
            {
                "case": "broken-stdout",
                "root": str(root),
                "argv": result.args,
                "native_exit": result.returncode,
                "stdout": None,
                "stderr": result.stderr.decode(),
                "before": before,
                "after": after,
                "reaped": True,
                "timed_out": False,
                "report_unobservable_closed_pipe": True,
            },
            stream,
            sort_keys=True,
        )
        stream.write("\n")
    assert result.returncode == 2
    assert result.stderr == b"output_failure: report emission failed.\n"
    assert after == before


def test_workflow_input_help() -> None:
    """Public help exposes the optional local projection rather than a hosted claim."""
    result = subprocess.run(
        source_python(str(SOURCE / "tools/check_workflow_policy.py"), "--help"),
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0 and not result.stderr
    assert b"--outcomes ROOT_RELATIVE_JSON_FILE" in result.stdout
    assert b"caller-supplied" in result.stdout
