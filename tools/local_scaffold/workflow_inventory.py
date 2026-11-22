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
            "sha256": "982becc527788a641398bd1b58a92ab023244b59cfbde493538476794867cb4a"
        },
        "docs.yml": {"sha256": "02b51c0875217321466ef5075116a52a911e34acbe7f3e546abcb0c730d9dd7a"},
        "pre-commit.yml": {
            "sha256": "e2265e62d228d97c26798d2beea050cfd06e15024da2d41c7eb3a2d3ce6bfeb3"
        },
        "sbom.yml": {"sha256": "da72e5ed1dfa0fa0aad90e38d0a62ae01abd807ec300f4d8a4732360cd0dcef7"},
        "scorecard.yml": {
            "sha256": "3bca83e30a04abda8135590a92b6039950375613fe2db9d2fe2e7766f967c664"
        },
        "security-audit.yml": {
            "sha256": "cb1ad4a657958288a3b191a90d04c79f27768ddb819822dd81be8187e05bd9df"
        },
    },
    "platform": "github.com",
    "step_inputs_sha256": {
        "ci.yml/complete": {
            "sha256": "27a8d67d28e7c37496270963292e378b2f9afa3bafdf3f98948e101a0851c1aa"
        },
        "codeql.yml/analysis": {
            "sha256": "b7f458a898040e207fe0af06abfe34f181c14252c391d113cda9993890909331"
        },
        "docs.yml/render": {
            "sha256": "23162d984fbe8e653c812b2253df02de6d940b9e331a5dc84d600eae763a6fd2"
        },
        "pre-commit.yml/quality": {
            "sha256": "fcad6635df4432d539fe7c6a5d81ada35ee50984c5f4a52c095302cd345eb5e8"
        },
        "pre-commit.yml/tests": {
            "sha256": "11a2c3de6fa2888ce3da61cfba89ee3b4fc2f95b2d2063cebe4ff1069b4db66b"
        },
        "sbom.yml/inventory": {
            "sha256": "8a91b8e417435f1c874f28efb502f106c8daa2c73863f074c31e8dd8cd7cdb95"
        },
        "scorecard.yml/configuration": {
            "sha256": "649f692c9cf810d7d344d0ec096da4b1a8b09cf8994077d72a65b2948ddbee13"
        },
        "security-audit.yml/dependency": {
            "sha256": "bab8d5ad519cb3f45de2e03db2fb0a3ab00dc7d0712d323bd543bc0d418c5e2d"
        },
        "security-audit.yml/secrets": {
            "sha256": "7aeed5f426860fbd0a61bf9919e329ae29131a1546eeb5ee68a5bddced8de94f"
        },
        "security-audit.yml/static": {
            "sha256": "b0f2da351285fa1ba6475fcd8f660921ee82ea1151e772ad5e099f2c53eadd64"
        },
        "security-audit.yml/workflow": {
            "sha256": "304b55a56ccd70c62984e6b5586d103d446d29c847202732676a12d6fc5ea47d"
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
