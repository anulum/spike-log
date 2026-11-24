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
            "sha256": "3bf8fb7d6533570c981280d0ed5925c35fde3c3bfb03862744ce1a1692071779"
        },
        "docs.yml": {"sha256": "84a30a3c1c0e5c1c0664bc258cad5a7ec20ebae18262596bbdada2c6b75cd07b"},
        "pre-commit.yml": {
            "sha256": "e1c5cc8d0867f1bdd7257ae18ef6ed0a6b0b50fed43f624689bd91feeda6717b"
        },
        "sbom.yml": {"sha256": "652617480569fff02f1b70f159277578a0645b05ee0fbccbfc5033613978a2a4"},
        "scorecard.yml": {
            "sha256": "e6bffa02aec736a980787c499db1bfea63455269e1a5a81954c67817055bf37c"
        },
        "security-audit.yml": {
            "sha256": "415408ee9979444792b0c5d5c9e0d4113c1e280581188322079f01d5cf484c6d"
        },
    },
    "platform": "github.com",
    "step_inputs_sha256": {
        "ci.yml/complete": {
            "sha256": "27a8d67d28e7c37496270963292e378b2f9afa3bafdf3f98948e101a0851c1aa"
        },
        "codeql.yml/analysis": {
            "sha256": "48328f4bfadd8bbdad888fea1b7b7885a0460b6dd0f9f5e44f3edfcf1df6b598"
        },
        "docs.yml/render": {
            "sha256": "34f0659b2746ad61658f66450cd580662b5eb63ab81473f790fc60d87c555a92"
        },
        "pre-commit.yml/quality": {
            "sha256": "5c00adc9257c0972b10d796cc3b94f654ad0c900f33df119f5725a25f825e24c"
        },
        "pre-commit.yml/tests": {
            "sha256": "75676cd8bfddd5aefe4b304d317867a13a8d3180cf0129ad21e647dfb7b33aa0"
        },
        "sbom.yml/inventory": {
            "sha256": "1b0d9fc698aaae5ce556aecc66a033283be509e4c5cd861bf3238a2f77111aa2"
        },
        "scorecard.yml/configuration": {
            "sha256": "e53130e4a57e6fe90d99c27ae12a0cb56cb5c9099e61f381bfacf099bbe4767a"
        },
        "security-audit.yml/dependency": {
            "sha256": "033561e96783de0939b89147122000b81c8c6ac30d14ddc05d4559de38a8e091"
        },
        "security-audit.yml/secrets": {
            "sha256": "c7c517277279c8be980943a89087cfa3612d0797810ae97aec3bc0328a5bc6df"
        },
        "security-audit.yml/static": {
            "sha256": "1113da185a664aa0d5d21914f09f03591a0d7177ec20c218de126f14fdf4f482"
        },
        "security-audit.yml/workflow": {
            "sha256": "913f63a965894307181a276168fc84220610f01d6434357a5c687d202e138d87"
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
        "actions/setup-python": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
        "github/codeql-action/init": "1bd86f2fdb4b86187fa4059f16f31a3202acc9ea",
        "github/codeql-action/analyze": "1bd86f2fdb4b86187fa4059f16f31a3202acc9ea",
    },
    "python_version": PYTHON_VERSION,
    "job_timeout_minutes": 20,
    "workflow_max_bytes": 102400,
    "workflow_max_lines": 1000,
    "permissions": {},
    "concurrency_group": "${{ github.workflow }}-${{ github.ref }}",
    "cancel_in_progress": True,
}
