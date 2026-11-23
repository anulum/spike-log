# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance


"""Reviewed workflow inventory constants for local repository validation."""

from typing import Final, TypedDict

from .bootstrap_bindings import PYTHON_VERSION


class WorkflowSpec(TypedDict):
    """The exact trigger and job inventory for one reviewed analysis workflow."""

    triggers: list[str]
    jobs: list[str]


class JobSpec(TypedDict, total=False):
    """One owned job and its fixed command or same-revision reusable call."""

    owner: str
    category: int
    needs: list[str]
    command: str
    uses: str


class StepSource(TypedDict):
    """Explicit algorithm and digest for one complete parsed step sequence."""

    sha256: str


class WorkflowPolicy(TypedDict):
    """Closed build-time workflow parameters; input cannot weaken safety policy."""

    schema_revision: str
    workflows: dict[str, WorkflowSpec]
    jobs: dict[str, JobSpec]
    actions: dict[str, str]
    python_version: str
    job_timeout_minutes: int
    workflow_max_bytes: int
    workflow_max_lines: int
    permissions: dict[str, str]
    concurrency_group: str
    cancel_in_progress: bool
    platform: str
    step_inputs_sha256: dict[str, StepSource]
    workflow_inputs_sha256: dict[str, StepSource]


WORKFLOW_POLICY: Final[WorkflowPolicy] = {
    "workflow_inputs_sha256": {
        "ci.yml": {"sha256": "64445a0ef5fe296928ae6f30370aaf2626703dfe06bc2d8c8f8f17500b45baaa"},
        "codeql.yml": {
            "sha256": "5894072b3ef5202cd3898baf48432790a012420b3acb0ad22d42362c0e642ff2"
        },
        "docs.yml": {"sha256": "659ee2025bd65eaa6075a1a1a622b0d8ce31bb6eae9b1310b3bf286b7d2e0a66"},
        "pre-commit.yml": {
            "sha256": "665e96983cc27ab64d58031cbe3165d26e7361f4e83a55c24722d25720de7b18"
        },
        "sbom.yml": {"sha256": "e99b2deca417a57fa4a841cf00b4de53d74aa3db87893f3802335cda462b235d"},
        "scorecard.yml": {
            "sha256": "ab22da234019cf258e6ab51fe4ecbe2cca4e6c50a4776d4813812b1215f6b274"
        },
        "security-audit.yml": {
            "sha256": "e49c4d3b5ee2d2c4017e5a6f2db8fb2979db7d543cb5f48a9eb1c6abb5cff4d0"
        },
    },
    "platform": "github.com",
    "step_inputs_sha256": {
        "ci.yml/complete": {
            "sha256": "27a8d67d28e7c37496270963292e378b2f9afa3bafdf3f98948e101a0851c1aa"
        },
        "codeql.yml/analysis": {
            "sha256": "b789f782f2137eee497ddb7c7c1579511a71f8fca0fd603a6c47bbdb988f10e5"
        },
        "docs.yml/render": {
            "sha256": "7c259ef152e4b1af189fb93627bc334b31240774c03301e0e247311606e9c140"
        },
        "pre-commit.yml/quality": {
            "sha256": "3fe32e4f3e58a50a14cc19e3a618190c373621092e23653515fc5ef60544825c"
        },
        "pre-commit.yml/tests": {
            "sha256": "d888915f04243078ed5a6a2157b818862e68d36c8aad5f3f783ca4e2f63da81c"
        },
        "sbom.yml/inventory": {
            "sha256": "af0c9b9f07b280700eb16178e5baef8f32538ad428e07c02fb198cf44d3d0e73"
        },
        "scorecard.yml/configuration": {
            "sha256": "c68e4685863ec0111ff89ede93e1ce35169dbcdf0ea6174a78c21e8b2d74314f"
        },
        "security-audit.yml/dependency": {
            "sha256": "b389aaf3940665506360e7793f6011d4757338f5c57d34f6e05915799b3dcf60"
        },
        "security-audit.yml/secrets": {
            "sha256": "b824fe3f41bb7158757b5c01939e8f3697b2c33d1647a54a34f938a4cc9eb75f"
        },
        "security-audit.yml/static": {
            "sha256": "5edbbe42de19572f57dbc516cc2594f70cd7c319a6fc38f1c6bfc6d7f04565a4"
        },
        "security-audit.yml/workflow": {
            "sha256": "8bc2e4f5769b77ebf5d6a64096fd9c76deaad033ed2ebf4de7fc3149f86ff0c9"
        },
    },
    "schema_revision": "spike_log.local-workflow-policy.v1",
    "workflows": {
        "pre-commit.yml": {
            "triggers": ["workflow_call", "workflow_dispatch"],
            "jobs": ["quality", "tests"],
        },
        "docs.yml": {"triggers": ["workflow_call", "workflow_dispatch"], "jobs": ["render"]},
        "codeql.yml": {"triggers": ["workflow_call", "workflow_dispatch"], "jobs": ["analysis"]},
        "security-audit.yml": {
            "triggers": ["workflow_call", "workflow_dispatch"],
            "jobs": ["dependency", "static", "secrets", "workflow"],
        },
        "sbom.yml": {"triggers": ["workflow_call", "workflow_dispatch"], "jobs": ["inventory"]},
        "scorecard.yml": {
            "triggers": ["workflow_call", "workflow_dispatch"],
            "jobs": ["configuration"],
        },
        "ci.yml": {
            "triggers": ["push", "pull_request", "workflow_dispatch"],
            "jobs": [
                "pre-commit",
                "docs",
                "codeql",
                "security-audit",
                "sbom",
                "scorecard",
                "complete",
            ],
        },
    },
    "jobs": {
        "pre-commit.yml/quality": {
            "owner": "local-validation-maintainer",
            "category": 2,
            "needs": [],
            "command": "make quality",
        },
        "pre-commit.yml/tests": {
            "owner": "local-validation-maintainer",
            "category": 4,
            "needs": [],
            "command": "make test",
        },
        "docs.yml/render": {
            "owner": "local-validation-maintainer",
            "category": 9,
            "needs": [],
            "command": "make docs",
        },
        "codeql.yml/analysis": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make source-analysis",
        },
        "security-audit.yml/dependency": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make dependency-security",
        },
        "security-audit.yml/static": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make static-security",
        },
        "security-audit.yml/secrets": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make secret-scan",
        },
        "security-audit.yml/workflow": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make workflow-security",
        },
        "sbom.yml/inventory": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make sbom",
        },
        "scorecard.yml/configuration": {
            "owner": "local-validation-maintainer",
            "category": 8,
            "needs": [],
            "command": "make supply-chain",
        },
        "ci.yml/pre-commit": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/pre-commit.yml",
        },
        "ci.yml/docs": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/docs.yml",
        },
        "ci.yml/codeql": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/codeql.yml",
        },
        "ci.yml/security-audit": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/security-audit.yml",
        },
        "ci.yml/sbom": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/sbom.yml",
        },
        "ci.yml/scorecard": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": [],
            "uses": "$/.github/workflows/scorecard.yml",
        },
        "ci.yml/complete": {
            "owner": "local-validation-maintainer",
            "category": 1,
            "needs": ["pre-commit", "docs", "codeql", "security-audit", "sbom", "scorecard"],
            "command": "aggregate_all_six",
        },
    },
    "actions": {
        "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
        "github/codeql-action/init": "2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
        "github/codeql-action/analyze": "2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2",
    },
    "python_version": PYTHON_VERSION,
    "job_timeout_minutes": 20,
    "workflow_max_bytes": 102400,
    "workflow_max_lines": 1000,
    "permissions": {},
    "concurrency_group": "${{ github.workflow }}-${{ github.ref }}",
    "cancel_in_progress": True,
}
