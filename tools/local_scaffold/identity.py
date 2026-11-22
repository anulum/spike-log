# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance


"""Reviewed identity constants for local repository validation."""

from typing import Final

REPOSITORY: Final = "SPIKE-LOG"


GROUP: Final = "SC-NEUROMORPHIC-COMPUTING-SYSTEMS"

#: The Tier-0 lifecycle phase: the repository is published at its canonical public remote.
LIFECYCLE: Final = "public_repository"

#: The canonical public remote: the lower-case repository name under the owner account.
PUBLIC_REMOTE: Final = "https://github.com/anulum/spike-log"


PROFILE: Final = {
    "id": "gotm.enterprise-repository-tier0.local-scaffold",
    "revision": "2026-10-04",
    "standard_sha256": "8421674a61444474447fad2f4d2bfc54dc5a1ea12ae988785e57dbcab385938c",
    "profile_sha256": "f453a70eae008c41f8d26a1f495ec3636f64739bcedb9caac0bdf8774300905c",
}


SPDX_PREFIX: Final = "SPDX-License-Identifier" + ":"


HEADER: Final = [
    SPDX_PREFIX + " AGPL-3.0-or-later",
    "Commercial license available",
    "© Concepts 1996–2026 Miroslav Šotek. All rights reserved.",
    "© Code 2020–2026 Miroslav Šotek. All rights reserved.",
    "ORCID: 0009-0009-3560-0851",
    "Contact: www.anulum.li | protoscience@anulum.li",
    "SPIKE-LOG — source and configuration provenance",
]


REQUIRED: Final = [
    (".editorconfig", "file"),
    (".gitattributes", "file"),
    (".github/CODEOWNERS", "file"),
    (".github/FUNDING.yml", "file"),
    (".github/ISSUE_TEMPLATE/bug_report.yml", "file"),
    (".github/ISSUE_TEMPLATE/config.yml", "file"),
    (".github/ISSUE_TEMPLATE/feature_request.yml", "file"),
    (".github/dependabot.yml", "file"),
    (".github/pull_request_template.md", "file"),
    (".github/workflows/ci.yml", "file"),
    (".github/workflows/codeql.yml", "file"),
    (".github/workflows/docs.yml", "file"),
    (".github/workflows/pre-commit.yml", "file"),
    (".github/workflows/sbom.yml", "file"),
    (".github/workflows/scorecard.yml", "file"),
    (".github/workflows/security-audit.yml", "file"),
    (".gitignore", "file"),
    (".pre-commit-config.yaml", "file"),
    (".zenodo.json", "file"),
    ("ARCHITECTURE.md", "file"),
    ("CHANGELOG.md", "file"),
    ("CITATION.cff", "file"),
    ("CODE_OF_CONDUCT.md", "file"),
    ("CONTRIBUTING.md", "file"),
    ("CONTRIBUTORS.md", "file"),
    ("GOVERNANCE.md", "file"),
    ("LICENSE", "file"),
    ("LICENSES", "directory"),
    ("Makefile", "file"),
    ("NOTICE.md", "file"),
    ("README.md", "file"),
    ("REUSE.toml", "file"),
    ("ROADMAP.md", "file"),
    ("SECURITY.md", "file"),
    ("SUPPORT.md", "file"),
    ("VALIDATION.md", "file"),
    ("docs/ARCHITECTURE.md", "file"),
    ("docs/THREAT_MODEL.md", "file"),
    ("docs/adr/0001-repository-boundary.md", "file"),
    ("pyproject.toml", "file"),
    ("src/spike_log/__init__.py", "file"),
    ("src/spike_log/dvs_columns.py", "file"),
    ("src/spike_log/logical_records.py", "file"),
    ("src/spike_log/py.typed", "file"),
    ("src/spike_log/py.typed.license", "file"),
    ("docs/native-payloads.md", "file"),
    ("requirements-dev.txt", "file"),
    ("tests", "directory"),
    ("tools/preflight.py", "file"),
    ("repository-domain.json", "file"),
    ("schemas/repository-domain.schema.json", "file"),
    ("capability-inventory.json", "file"),
    ("mkdocs.yml", "file"),
    ("tools/check_repository_metadata.py", "file"),
    ("tools/check_source_provenance.py", "file"),
    ("tools/check_workflow_policy.py", "file"),
    ("tools/check_dependency_alignment.py", "file"),
    ("tools/check_documentation.py", "file"),
    ("tools/check_repository_inventory.py", "file"),
    ("docs/assets/anulum_logo_company.jpg", "file"),
    ("docs/assets/anulum_logo.png", "file"),
    ("docs/assets/fortis_studio_logo.jpg", "file"),
    ("repository-domain.json.license", "file"),
    ("schemas/repository-domain.schema.json.license", "file"),
    ("capability-inventory.json.license", "file"),
    (".zenodo.json.license", "file"),
    ("requirements-dev.in", "file"),
    ("dependency-provenance.json", "file"),
    ("dependency-provenance.json.license", "file"),
    ("docs/index.md", "file"),
    ("docs/validation-tooling.md", "file"),
    ("tests/test_repository_metadata.py", "file"),
    ("tests/test_source_provenance.py", "file"),
    ("tests/test_workflow_policy.py", "file"),
    ("tests/test_dependency_alignment.py", "file"),
    ("tests/test_documentation.py", "file"),
    ("tests/test_repository_inventory.py", "file"),
    ("tests/test_preflight.py", "file"),
    ("workflow-policy.json", "file"),
    ("workflow-policy.json.license", "file"),
    (".make/quality.mk", "file"),
    (".make/environment.mk", "file"),
    (".make/fixtures.mk", "file"),
    ("tools/reproduce_dependency_provenance.py", "file"),
]


FORBIDDEN: Final = [
    ".coordination",
    ".env",
    "04_ARCANE_SAPIENCE",
    "AGENTS.md",
    "BACKUP",
    "CLAUDE.md",
    "CODEX.md",
    "GEMINI.md",
    "GROK.md",
    "KIMI.md",
]


PLANNED: Final = ["spike_log.container.v1"]


FUNDING: Final = {
    "github": "anulum",
    "buy_me_a_coffee": "anulum",
    "custom": [
        "https://buy.stripe.com/4gM00kbiMdjAberaYz5J601",
        "https://www.paypal.com/donate?hosted_button_id=4X5F6DNT934HY",
        "https://go.twint.ch/1/e/tw?tw=acq.lJTAypb8SL2s8vPg7fL0ubi2C220ajOH0BEQn1aKfEJIiIakLpt8jlEv8XdQ9tCp.",
        "https://anulum.li/contact.html",
    ],
}


NATIVE_FILE_PURPOSES: Final = {
    "src/spike_log/container_digests.py": "SPIKE-LOG — native container digest preimages",
    "tests/domain/test_container_digests.py": "SPIKE-LOG — independent container digest preimages",
    "tests/test_environment_inputs.py": "SPIKE-LOG — actual pre-mutation environment checks",
    "tools/local_scaffold/bootstrap_bindings.py": "SPIKE-LOG — frozen environment input identities",
    "tools/local_scaffold/bootstrap_inputs.py": "SPIKE-LOG — read-only environment input verification",
    "tools/local_scaffold/bootstrap_cli.py": "SPIKE-LOG — environment input command",
    "tools/check_environment_inputs.py": "SPIKE-LOG — public environment input check",
    "tools/local_scaffold/provenance_wheels.py": "SPIKE-LOG — complete local wheel member and installed byte identity",
    "tools/local_scaffold/provenance_local.py": "SPIKE-LOG — hash-bound first-party and maintained dependency sources",
    "tests/test_provenance_local.py": "SPIKE-LOG — actual local dependency source reconstruction",
    "tests/test_provenance_local_boundaries.py": "SPIKE-LOG — local source refusal boundaries",
    "tests/domain/test_dvs_ordering.py": "SPIKE-LOG — declared event order and occurrence conservation",
    "tests/test_documentation_fragments.py": "SPIKE-LOG — actual Markdown fragment normalization and native hook wiring",
    "tests/test_processes.py": "SPIKE-LOG — synchronous process calling-context contract",
    "tests/test_provenance_record_identity.py": "SPIKE-LOG — native distribution and selected record version correspondence",
    "tests/test_report_scopes.py": "SPIKE-LOG — existing operation report scopes and owning consumers",
    "tools/local_scaffold/documentation_fragments.py": "SPIKE-LOG — canonical local documentation fragment spellings",
    "src/spike_log/__init__.py": "SPIKE-LOG — native event payload codecs",
    "src/spike_log/dvs_columns.py": "SPIKE-LOG — canonical DVS event columns",
    "src/spike_log/logical_records.py": "SPIKE-LOG — logical source record bytes",
    "tests/domain/__init__.py": "SPIKE-LOG — native format test namespace",
    "tests/domain/test_dvs_columns.py": "SPIKE-LOG — canonical event column contracts",
    "tests/domain/test_logical_records.py": "SPIKE-LOG — logical output record contracts",
    "docs/native-payloads.md": "SPIKE-LOG — native payload API and typing",
    "src/spike_log/py.typed.license": "SPIKE-LOG — native payload API and typing",
}


def source_header(name: str) -> list[str]:
    """Return the exact seven ownership fields for one maintained source kind.

    Parameters
    ----------
    name : str
        Lexical root-relative path; only fixed owned native paths use their
        descriptive module purpose. Unknown paths retain the original header.

    Returns
    -------
    list of str
        All six unchanged ownership fields and the exact fixed project purpose,
        detached from the installation constants.
    """
    return [*HEADER[:6], NATIVE_FILE_PURPOSES.get(name, HEADER[6])]
