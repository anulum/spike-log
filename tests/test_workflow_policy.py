# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise the real workflow graph and exact native aggregate state boundary."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

from local_scaffold.inputs import Json
from local_scaffold.reports import Fault, Report
from local_scaffold.workflows import (
    WorkflowSnapshot,
    collect,
    required_outcomes,
    same_revision_call,
    verify_snapshot,
)
from tests.conftest import change, payload, run_guard, snapshots


@pytest.mark.parametrize("size", [102400, 102401])
def test_public_workflow_original_byte_limit(root: Path, size: int) -> None:
    """The actual public workflow consumer accepts its byte cap and refuses one extra."""
    path = root / ".github/workflows/pre-commit.yml"
    original = path.read_bytes()
    path.write_bytes(original + b"\n# " + b"x" * (size - len(original) - 4) + b"\n")
    assert len(path.read_bytes()) == size
    before = snapshots(root)
    result = payload(run_guard("workflow_policy", root), 0 if size == 102400 else 2)
    if size == 102401:
        reasons = result["reasons"]
        assert isinstance(reasons, list)
        assert any(
            isinstance(reason, dict)
            and reason["code"] == "resource_limit"
            and reason["location"] == ".github/workflows/pre-commit.yml"
            for reason in reasons
        )
    assert snapshots(root) == before


def test_public_workflow_original_line_limit_refuses(root: Path) -> None:
    """An actual bounded workflow exceeding 1000 lines refuses before interpretation."""
    path = root / ".github/workflows/pre-commit.yml"
    path.write_bytes(path.read_bytes() + b"\n# Actual received workflow comment.\n" * 1001)
    assert len(path.read_bytes()) < 102400
    assert len(path.read_text().splitlines()) > 1000
    before = snapshots(root)
    result = payload(run_guard("workflow_policy", root), 2)
    reasons = result["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict)
        and reason["code"] == "workflow_policy.size-limit"
        and reason["location"] == ".github/workflows/pre-commit.yml"
        for reason in reasons
    )
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "case",
    [
        "unknown-job",
        "duplicate-owner",
        "missing-required",
        "path-filter",
        "tag-pin",
        "fake-commit",
        "write-permission",
        "credential-persist",
        "pull-request-target",
        "dependency-cycle",
        "foreign-reusable",
        "timeout",
        "skipped",
        "bad-job",
        "bad-step",
        "bad-steps",
        "bad-action",
        "setup-python",
        "no-jobs",
        "bad-trigger",
        "concurrency",
    ],
)
def test_workflow_graph_refusals(root: Path, case: str) -> None:
    """Mutate actual graph inputs without substituting or fabricating tool output."""
    if case == "duplicate-owner":
        change(root, "workflow-policy.json", ("jobs",), {})
    else:
        filename = (
            "ci.yml"
            if case
            in ("path-filter", "pull-request-target", "dependency-cycle", "foreign-reusable")
            else "pre-commit.yml"
        )
        path = root / ".github/workflows" / filename
        loaded = cast(dict[object, Json], yaml.safe_load(path.read_text()))
        data = {"on" if key is True else str(key): value for key, value in loaded.items()}
        jobs = cast(dict[str, Json], data["jobs"])
        key = next(iter(jobs))
        job = cast(dict[str, Json], jobs[key])
        steps = cast(list[Json], job.get("steps", []))
        if case == "unknown-job":
            jobs["unapproved"] = {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}
        elif case == "missing-required":
            jobs.pop(key)
        elif case == "path-filter":
            data["on"] = {
                "push": {"paths-ignore": ["tools/**"]},
                "pull_request": {},
                "workflow_dispatch": {},
            }
        elif case == "pull-request-target":
            data["on"] = {"pull_request_target": {}}
        elif case == "dependency-cycle":
            job["needs"] = ["complete"]
        elif case == "foreign-reusable":
            job["uses"] = "foreign/project/.github/workflows/task.yml@main"
        elif case == "write-permission":
            job["permissions"] = {"contents": "write"}
        elif case == "timeout":
            job["timeout-minutes"] = 21
        elif case == "skipped":
            job["continue-on-error"] = True
        elif case == "bad-job":
            jobs[key] = False
        elif case == "bad-steps":
            job["steps"] = {}
        elif case == "bad-step":
            steps.append(False)
        elif case == "no-jobs":
            data["jobs"] = []
        elif case == "bad-trigger":
            data["on"] = []
        elif case == "concurrency":
            data["concurrency"] = {}
        else:
            step = cast(dict[str, Json], steps[0 if case != "setup-python" else 1])
            if case == "tag-pin":
                step["uses"] = "actions/checkout@v4"
            elif case == "fake-commit":
                step["uses"] = "actions/checkout@" + "0" * 40
            elif case == "bad-action":
                step["uses"] = True
            elif case == "credential-persist":
                step["with"] = {"persist-credentials": True}
            else:
                step["with"] = {"python-version": "3.14"}
        path.write_text(yaml.safe_dump(data, sort_keys=False))
    payload(
        run_guard("workflow_policy", root),
        2
        if case not in ("bad-job", "bad-steps", "bad-step", "bad-action", "no-jobs")
        else 4
        if case in ("bad-job", "bad-step", "no-jobs")
        else 2,
    )


@pytest.mark.parametrize(
    "case",
    [
        "policy-shape",
        "step-skipped",
        "root-write",
        "reusable-skipped",
        "aggregate-condition",
        "removed-command",
    ],
)
def test_actual_complete_graph_failures(root: Path, case: str) -> None:
    """Refuse distinct real policy, permission, call and aggregate graph changes."""
    if case == "policy-shape":
        (root / "workflow-policy.json").write_text("[]\n")
    else:
        filename = "pre-commit.yml" if case in ("step-skipped", "removed-command") else "ci.yml"
        path = root / ".github/workflows" / filename
        loaded = cast(dict[object, Json], yaml.safe_load(path.read_text()))
        data = {"on" if key is True else str(key): value for key, value in loaded.items()}
        jobs = cast(dict[str, Json], data["jobs"])
        if case == "root-write":
            data["permissions"] = {"contents": "write"}
        elif case == "reusable-skipped":
            cast(dict[str, Json], jobs["docs"])["if"] = "false"
        elif case == "aggregate-condition":
            cast(dict[str, Json], jobs["complete"])["if"] = "false"
        else:
            job = cast(dict[str, Json], next(iter(jobs.values())))
            steps = cast(list[dict[str, Json]], job["steps"])
            if case == "step-skipped":
                steps[0]["continue-on-error"] = True
            else:
                for step in steps:
                    if "run" in step:
                        step["run"] = "true"
        path.write_text(yaml.safe_dump(data, sort_keys=False))
    report = payload(run_guard("workflow_policy", root), 2)
    reasons = cast(list[dict[str, Json]], report["reasons"])
    expected = {
        "policy-shape": "policy_refusal",
        "step-skipped": "workflow_policy.aggregate-skipped",
        "root-write": "workflow_policy.write-permission",
        "reusable-skipped": "workflow_policy.aggregate-skipped",
        "aggregate-condition": "workflow_policy.aggregate-skipped",
        "removed-command": "workflow_policy.missing-required",
    }[case]
    assert any(reason["code"] == expected for reason in reasons)


@pytest.mark.parametrize("state", ["success", "failure", "cancelled", "skipped", "not_run"])
def test_actual_aggregate_states(state: str) -> None:
    """Require every declared workflow result rather than accepting omitted work."""
    assert not required_outcomes({})
    actual = {
        name: "success"
        for name in ("pre-commit", "docs", "codeql", "security-audit", "sbom", "scorecard")
    }
    actual["docs"] = state
    assert required_outcomes(actual) == (state == "success")


def test_complete_workflows_are_readonly(root: Path) -> None:
    """The complete actual graph gate is deterministic and leaves inputs intact."""
    before = snapshots(root)
    a = run_guard("workflow_policy", root)
    b = run_guard("workflow_policy", root)
    payload(a, 0)
    assert a.stdout == b.stdout
    assert snapshots(root) == before


TARGETS = (
    "pre-commit.yml",
    "docs.yml",
    "codeql.yml",
    "security-audit.yml",
    "sbom.yml",
    "scorecard.yml",
)


@pytest.mark.parametrize("target", TARGETS)
def test_six_actual_same_revision_calls(root: Path, target: str) -> None:
    """Each fixed call validates through the actual complete inventory and CLI."""
    assert same_revision_call("$/.github/workflows/" + target, target)
    result = run_guard("workflow_policy", root)
    payload(result, 0)


@pytest.mark.parametrize(
    "case",
    [
        "suffix",
        "expression",
        "wrong",
        "missing",
        "duplicate",
        "omitted",
        "unsupported-host",
        "old-syntax",
        "unknown-target",
        "non-string",
    ],
)
def test_dedicated_reference_refusals(root: Path, case: str) -> None:
    """Exercise exact native graph refusals without auto-fix or unsupported fallback."""
    if case == "unsupported-host":
        change(root, "workflow-policy.json", ("platform",), "github_enterprise_server")
        assert not same_revision_call(
            "$/.github/workflows/docs.yml", "docs.yml", "github_enterprise_server"
        )
    elif case == "missing":
        (root / ".github/workflows/docs.yml").unlink()
    else:
        path = root / ".github/workflows/ci.yml"
        loaded = cast(dict[object, Json], yaml.safe_load(path.read_text()))
        data = {"on" if key is True else str(key): value for key, value in loaded.items()}
        jobs = cast(dict[str, Json], data["jobs"])
        job = cast(dict[str, Json], jobs["docs"])
        if case == "suffix":
            job["uses"] = "$/.github/workflows/docs.yml@main"
        elif case == "expression":
            job["uses"] = "${{ github.repository }}/.github/workflows/docs.yml"
        elif case == "wrong":
            job["uses"] = "$/.github/workflows/pre-commit.yml"
        elif case == "duplicate":
            jobs["docs-duplicate"] = dict(job)
        elif case == "omitted":
            jobs.pop("docs")
        elif case == "old-syntax":
            job["uses"] = "./.github/workflows/docs.yml"
        elif case == "unknown-target":
            job["uses"] = "$/.github/workflows/unknown.yml"
        else:
            job["uses"] = False
        path.write_text(yaml.safe_dump(data, sort_keys=False))
    payload(run_guard("workflow_policy", root), 3 if case == "missing" else 2)
    assert not same_revision_call("$/.github/workflows/unknown.yml", "unknown.yml")


@pytest.mark.parametrize(
    "state",
    ["success", "failure", "skipped", "cancelled", "not_run", "missing", "foreign", "extra"],
)
def test_actual_stable_gate_program(root: Path, state: str) -> None:
    """The real workflow aggregate accepts exactly six named successful outcomes."""
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    script = workflow["jobs"]["complete"]["steps"][0]["run"]
    program = script.split("'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    required = ("pre-commit", "docs", "codeql", "security-audit", "sbom", "scorecard")
    results = {name: {"result": "success"} for name in required}
    if state == "missing":
        results.pop("docs")
    elif state == "foreign":
        results["unrequired"] = results.pop("docs")
    elif state == "extra":
        results["unrequired"] = {"result": "success"}
    elif state != "success":
        results["docs"]["result"] = state
    environment = os.environ.copy()
    environment["REQUIRED_RESULTS"] = json.dumps(results)
    result = subprocess.run(
        [sys.executable, "-I", "-c", program],
        env=environment,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == (0 if state == "success" else 1)
    assert not result.stdout and not result.stderr


def test_actual_aggregate_all_return_combinations(root: Path) -> None:
    """Execute the actual aggregate body for every six-job return combination."""
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    script = workflow["jobs"]["complete"]["steps"][0]["run"]
    program = script.split("'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    driver = """import itertools,json,os,sys
program=compile(sys.stdin.read(),'<actual-ci-complete>','exec')
roles=('pre-commit','docs','codeql','security-audit','sbom','scorecard')
accepted=[]
observed=0
for states in itertools.product(('success','failure','cancelled','skipped'),repeat=6):
    os.environ['REQUIRED_RESULTS']=json.dumps({role:{'result':state} for role,state in zip(roles,states,strict=True)})
    try:
        exec(program,{'__name__':'__main__'})
    except SystemExit as error:
        assert error.code==1,(states,error.code)
    else:
        accepted.append(states)
    observed+=1
assert accepted==[('success',)*6],accepted
assert observed==4096,observed
print(observed)
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", driver],
        input=program.encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == b"4096\n" and not result.stderr


@pytest.mark.parametrize("case", ["extra-workflow-entry", "unreadable-workflow-directory"])
def test_actual_graph_discovery_refusals(root: Path, case: str) -> None:
    """Real directory excess or denied discovery never yields a complete graph."""
    directory = root / ".github/workflows"
    expected = 2
    if case == "extra-workflow-entry":
        (directory / "additional.yml").write_text("{}\n")
    else:
        assert os.geteuid() != 0, "Privileged access cannot qualify denied discovery."
        directory.chmod(0)
        expected = 3
    try:
        report = payload(run_guard("workflow_policy", root), expected)
        reasons = cast(list[dict[str, Json]], report["reasons"])
        assert [reason["code"] for reason in reasons] == [
            "workflow_policy.missing-required" if expected == 2 else "input_unavailable"
        ]
    finally:
        if case == "unreadable-workflow-directory":
            directory.chmod(0o700)


@pytest.mark.parametrize("case", ["directory-inventory", "missing-raw-workflow"])
def test_documented_snapshot_input_integrity(root: Path, case: str) -> None:
    """The documented retained-input API refuses incomplete caller snapshots."""
    original = collect(root)
    report = Report("workflow_policy")
    if case == "directory-inventory":
        received = WorkflowSnapshot(original.policy, original.entries[:-1], original.workflows)
        verify_snapshot(received, report)
        assert report.exit_code == 2
        assert [reason["code"] for reason in report.reasons] == ["workflow_policy.missing-required"]
    else:
        received = WorkflowSnapshot(original.policy, original.entries, original.workflows[:-1])
        with pytest.raises(Fault) as observed:
            verify_snapshot(received, report)
        assert observed.value.code == "workflow_policy.missing-required"
