# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance


"""Reviewed workflow inventory constants for local repository validation."""

from typing import Final, TypedDict


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
            "sha256": "b8070022ae6f055c6e18f6f68d3c86942f77886cf2889f9b18313a2895133026"
        },
        "docs.yml": {"sha256": "b46ea20d84aecf020a044e2e9027b25d4ef86f39bf88991ba03fac27e0ebc923"},
        "pre-commit.yml": {
            "sha256": "18eac81409a6a6a1f3015672cc3a6d93f44fb709b218dc469564485586c8e1f4"
        },
        "sbom.yml": {"sha256": "b10efa2f8b58d5862a78d914a9ee8b202e00ff4121f60e1cc878d664792ee633"},
        "scorecard.yml": {
            "sha256": "3825a426cd9cf5f86f720c06a86d2f88563db05ba955766821ab6880181930fa"
        },
        "security-audit.yml": {
            "sha256": "2bbf2bb84e811336dab45e6d29fdb805e0d951aaaffd5ec77be70c42d3fc4cc1"
        },
    },
    "platform": "github.com",
    "step_inputs_sha256": {
        "ci.yml/complete": {
            "sha256": "27a8d67d28e7c37496270963292e378b2f9afa3bafdf3f98948e101a0851c1aa"
        },
        "codeql.yml/analysis": {
            "sha256": "af54aee82a72470f165c0646cbe248ab5145aa4343eb8cc3089ce273dcab62cc"
        },
        "docs.yml/render": {
            "sha256": "4f02ccb414cf3fe313cb3ac89efcc04370ca21a1d5cb6608690444fd68fab504"
        },
        "pre-commit.yml/quality": {
            "sha256": "046a65674f42b81a1e479fdc11ffbf0c1e4d1f0fdd04db31f4c9d022d758f80c"
        },
        "pre-commit.yml/tests": {
            "sha256": "9b7e11e5c4dace5572f246a236ef4e2dcf28af9bd6ecbe8078f53c515096de91"
        },
        "sbom.yml/inventory": {
            "sha256": "82c8170a72779c6f11e3b5952d733a9a5b270343b51e6d00ef03bc7c76b2a5f5"
        },
        "scorecard.yml/configuration": {
            "sha256": "23f786a103ebd0d84ff0f532497be54086ab0226298ad1060cb7a56f909b0398"
        },
        "security-audit.yml/dependency": {
            "sha256": "75af670fd9bcc7dba839020144e2353ead5b778265a8c2a588740cc79f96462a"
        },
        "security-audit.yml/secrets": {
            "sha256": "0572f967301b5a8e0ecf57caeba48f6c81bbdc16cb543529ac3e0eb91ca8b1fb"
        },
        "security-audit.yml/static": {
            "sha256": "189c0e83494a277eba2071f565b3b93bef51b377fc6554e973dfd561a243e563"
        },
        "security-audit.yml/workflow": {
            "sha256": "41f9313691b397ab6dfd9766b9e06c9c9e8ba223ecb672dddfa060fbfe02ade6"
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
    "python_version": "3.13.16",
    "job_timeout_minutes": 20,
    "workflow_max_bytes": 102400,
    "workflow_max_lines": 1000,
    "permissions": {},
    "concurrency_group": "${{ github.workflow }}-${{ github.ref }}",
    "cancel_in_progress": True,
}
