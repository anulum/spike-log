# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check the complete same-revision analysis graph and immutable action producers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .inputs import Json, json_object, parse_json, parse_yaml, read_bytes, relative_path
from .policy import ACTIONS, WORKFLOW_POLICY
from .production_names import check_values
from .reports import Fault, Report


@dataclass(frozen=True, slots=True)
class WorkflowSnapshot:
    """Immutable complete raw policy, directory inventory and seven workflow inputs.

    Attributes
    ----------
    policy : bytes
        Complete original bounded workflow-policy bytes.
    entries : tuple[str, ...]
        Sorted full original workflow directory population.
    workflows : tuple[tuple[str, bytes], ...]
        Every owned original workflow filename and its complete bounded bytes.
    """

    policy: bytes
    entries: tuple[str, ...]
    workflows: tuple[tuple[str, bytes], ...]


def collect(root: Path) -> WorkflowSnapshot:
    """Collect the entire finite original set with no-follow bounded file reads.

    Parameters
    ----------
    root : Path
        Repository supplying its original workflow policy and complete seven-file workflow directory.

    Returns
    -------
    WorkflowSnapshot
        Retained complete policy bytes, sorted directory entries and every original bounded workflow byte string.

    Raises
    ------
    Fault
        Raised for unavailable/unsafe input or a directory population exceeding the fixed seven entries.
    """
    policy = read_bytes(root, "workflow-policy.json")
    directory = relative_path(root, ".github/workflows")
    entries: list[str] = []
    try:
        for path in directory.iterdir():
            entries.append(path.name)
            if len(entries) > 7:
                raise Fault("workflow_policy.missing-required", ".github/workflows")
    except OSError as error:
        raise Fault("input_unavailable", ".github/workflows", 3) from error
    workflows = tuple(
        (name, read_bytes(root, ".github/workflows/" + name, 102400))
        for name in WORKFLOW_POLICY["workflows"]
    )
    return WorkflowSnapshot(policy, tuple(sorted(entries)), workflows)


def same_revision_call(value: object, target: str, platform: str = "github.com") -> bool:
    """Validate one exact prepared cloud call with no ref/expression or host fallback.

    Parameters
    ----------
    value : object
        Actual received workflow call spelling.
    target : str
        One of the six explicitly owned prepared reusable workflow filenames.
    platform : str
        Prepared host identity; only github.com is admitted.

    Returns
    -------
    bool
        True only for the exact dedicated same-repository call with no explicit ref, expression or alternate host.
    """
    allowed = {
        "pre-commit.yml",
        "docs.yml",
        "codeql.yml",
        "security-audit.yml",
        "sbom.yml",
        "scorecard.yml",
    }
    return (
        platform == "github.com" and target in allowed and value == "$/.github/workflows/" + target
    )


def required_outcomes(outcomes: dict[str, str]) -> bool:
    """Require exactly all six workflow returns, each observed as success.

    Parameters
    ----------
    outcomes : dict[str, str]
        Decoded role-to-status mapping for the six reusable workflow returns.

    Returns
    -------
    bool
        True only for the exact complete role set with every status equal to success.
    """
    required = set(WORKFLOW_POLICY["workflows"]["ci.yml"]["jobs"]) - {"complete"}
    return set(outcomes) == required and all(status == "success" for status in outcomes.values())


def verify_outcomes(root: Path, name: str, report: Report) -> None:
    """Validate one bounded local projection without authenticating a hosted run.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Relative local JSON projection filename, not a hosted authentication source.
    report : Report
        Receives aggregate-skipped when any complete admitted role outcome is not success.

    Raises
    ------
    Fault
        Raised for missing/unknown/invalid outcome members or bounded input refusal.
    """
    received = json_object(root, name)
    required = set(WORKFLOW_POLICY["workflows"]["ci.yml"]["jobs"]) - {"complete"}
    if set(received) != required:
        raise Fault("policy_refusal", name)
    outcomes: dict[str, str] = {}
    for role, value in received.items():
        if not isinstance(value, str) or value not in {
            "success",
            "failure",
            "cancelled",
            "skipped",
            "not_run",
        }:
            raise Fault("policy_refusal", name)
        outcomes[role] = value
    if not required_outcomes(outcomes):
        report.add("workflow_policy.aggregate-skipped", name)


def inspect_steps(steps: list[Json], name: str, report: Report) -> None:
    """Refuse mutable actions, persistent credentials and unreviewed commands.

    Parameters
    ----------
    steps : list[Json]
        Received step sequence from an owned workflow job.
    name : str
        Workflow lexical location for safe findings.
    report : Report
        Receives unpinned action, persistent credential, wrong command or malformed-step refusals.
    """
    for step in steps:
        if not isinstance(step, dict):
            report.add("configuration_invalid", name, 4)
            continue
        uses = step.get("uses")
        if uses is not None:
            if not isinstance(uses, str) or "@" not in uses:
                report.add("workflow_policy.tag-pin", name)
                continue
            action, revision = uses.rsplit("@", 1)
            if not re.fullmatch(r"[0-9a-f]{40}", revision):
                report.add("workflow_policy.tag-pin", name)
            elif ACTIONS.get(action) != revision:
                report.add("workflow_policy.fake-commit", name)
            if action == "actions/checkout":
                options = step.get("with")
                if not isinstance(options, dict) or options.get("persist-credentials") is not False:
                    report.add("workflow_policy.credential-persist", name)
            if action == "actions/setup-python":
                options = step.get("with")
                if not isinstance(options, dict) or options.get("python-version") != "3.13.16":
                    report.add("dependency_alignment.hook-drift", name)
        if any(key in step for key in ("continue-on-error",)):
            report.add("workflow_policy.aggregate-skipped", name)


def verify(root: Path, report: Report) -> None:
    """Validate one owner per job and the entire reviewed read-only workflow DAG.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives complete static workflow policy/ownership/permission/pin/trigger/graph findings.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable/unbounded or malformed original workflow inputs.
    """
    verify_snapshot(collect(root), report)


def verify_snapshot(snapshot: WorkflowSnapshot, report: Report) -> dict[str, dict[str, Json]]:
    """Validate and return the same complete retained inputs for an analyser view.

    Parameters
    ----------
    snapshot : WorkflowSnapshot
        Complete retained original policy, directory and workflow bytes, all checked together.
    report : Report
        Receives complete static workflow findings without rereading a different candidate.

    Returns
    -------
    dict[str, dict[str, Json]]
        All parsed original workflow objects from this same snapshot; admission also requires report.exit_code zero.

    Raises
    ------
    Fault
        Raised for unsafe/malformed/unbounded retained policy/workflow bytes.
    """
    actual_policy = parse_json(snapshot.policy, "workflow-policy.json")
    if not isinstance(actual_policy, dict):
        raise Fault("policy_refusal", "workflow-policy.json")
    if actual_policy != WORKFLOW_POLICY:
        report.add("workflow_policy.duplicate-owner", "workflow-policy.json")
    if actual_policy.get("platform") != "github.com":
        report.add("workflow_policy.foreign-reusable", "workflow-policy.json")
    expected_files = set(WORKFLOW_POLICY["workflows"])
    if set(snapshot.entries) != expected_files:
        report.add("workflow_policy.missing-required", ".github/workflows")
    originals = dict(snapshot.workflows)
    if set(originals) != expected_files or len(snapshot.workflows) != 7:
        raise Fault("workflow_policy.missing-required", ".github/workflows")
    accepted: dict[str, dict[str, Json]] = {}
    for filename, obligation in WORKFLOW_POLICY["workflows"].items():
        name = ".github/workflows/" + filename
        workflow = parse_yaml(originals[filename], name, workflow=True)
        check_values(workflow, name, report)
        accepted[filename] = workflow
        digest = hashlib.sha256(
            json.dumps(workflow, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
        ).hexdigest()
        if digest != WORKFLOW_POLICY["workflow_inputs_sha256"][filename]["sha256"]:
            report.add("policy_refusal", name)
        if workflow.get("permissions") != {}:
            report.add("workflow_policy.write-permission", name)
        triggers = workflow.get("on")
        if not isinstance(triggers, dict) or set(triggers) != set(obligation["triggers"]):
            report.add("workflow_policy.pull-request-target", name)
        else:
            for trigger in triggers.values():
                if isinstance(trigger, dict) and any(
                    k in trigger for k in ("paths", "paths-ignore", "branches-ignore")
                ):
                    report.add("workflow_policy.path-filter", name)
        concurrency = workflow.get("concurrency")
        if concurrency != {
            "group": WORKFLOW_POLICY["concurrency_group"],
            "cancel-in-progress": True,
        }:
            report.add("workflow_policy.aggregate-skipped", name)
        jobs = workflow.get("jobs")
        if not isinstance(jobs, dict):
            report.add("configuration_invalid", name, 4)
            continue
        if set(jobs) != set(obligation["jobs"]):
            report.add("workflow_policy.unknown-job", name)
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                report.add("configuration_invalid", name, 4)
                continue
            expected = WORKFLOW_POLICY["jobs"].get(filename + "/" + job_id)
            if expected is None:
                continue
            permission = job.get("permissions")
            if permission not in ({"contents": "read"}, {}):
                report.add("workflow_policy.write-permission", name)
            needs = job.get("needs", [])
            if needs != expected["needs"]:
                report.add("workflow_policy.dependency-cycle", name)
            if "uses" in expected:
                if not same_revision_call(job.get("uses"), expected["uses"].rsplit("/", 1)[-1]):
                    report.add("workflow_policy.foreign-reusable", name)
                if "if" in job or "secrets" in job or "with" in job:
                    report.add("workflow_policy.aggregate-skipped", name)
                continue
            timeout = job.get("timeout-minutes")
            if type(timeout) is not int or timeout <= 0 or timeout > 20:
                report.add("workflow_policy.timeout", name)
            steps = job.get("steps")
            if not isinstance(steps, list) or not steps:
                report.add("workflow_policy.missing-required", name)
                continue
            inspect_steps(steps, name, report)
            step_digest = hashlib.sha256(
                json.dumps(steps, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
            ).hexdigest()
            if (
                step_digest
                != WORKFLOW_POLICY["step_inputs_sha256"][filename + "/" + job_id]["sha256"]
            ):
                report.add("workflow_policy.missing-required", name)
            runs = [step.get("run") for step in steps if isinstance(step, dict)]
            if job_id == "complete":
                if job.get("if") != "${{ always() }}" or not any(
                    isinstance(run, str)
                    and 'value["result"] != "success"' in run
                    and "set(results) != required" in run
                    for run in runs
                ):
                    report.add("workflow_policy.aggregate-skipped", name)
            elif expected["command"] not in runs:
                report.add("workflow_policy.missing-required", name)
            if "continue-on-error" in job or (job_id != "complete" and "if" in job):
                report.add("workflow_policy.aggregate-skipped", name)
    return accepted
