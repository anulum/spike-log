# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

.PHONY: quality test docs inventory-generate inventory preflight source-analysis static-security dependency-security secret-scan workflow-security sbom supply-chain

quality:
	$(PYTHON) -m ruff check --no-respect-gitignore src tools tests
	$(PYTHON) -m ruff format --check --no-respect-gitignore src tools tests
	$(PYTHON) -m mypy src tools tests
	$(PYTHON) -m ruff check --select D --no-respect-gitignore src tools tests

test:
	nice -n 19 $(PYTHON) -m pytest -n $(TEST_WORKERS) --dist=worksteal --basetemp=$(TEST_BASETEMP) --cov=spike_log --cov=tools --cov=tests --cov-branch --cov-fail-under=100 --cov-report=term-missing $(TEST_SELECTION)

docs:
	$(PYTHON) tools/check_documentation.py --root . --json

inventory-generate:
	$(PYTHON) tools/check_repository_inventory.py --root . --mode generate --output capability-inventory.json --json

inventory:
	$(PYTHON) tools/check_repository_inventory.py --root . --mode verify --json

preflight:
	$(PYTHON) tools/preflight.py --root . --profile local-scaffold --json

source-analysis:
	test ! -L .tool-cache
	test ! -L .tool-cache/bandit.json
	$(PYTHON) -I -m bandit --ini /dev/null --ignore-nosec --severity-level all --confidence-level all -r src tools -f json -o .tool-cache/bandit.json

static-security: source-analysis

dependency-security:
	$(PYTHON) tools/check_dependency_alignment.py --root . --json

secret-scan:
	test ! -e .gitleaksignore
	test ! -L .gitleaksignore
	.tool-cache/native/gitleaks/gitleaks dir --redact --no-banner --log-level error --ignore-gitleaks-allow --gitleaks-ignore-path /dev/null --config gitleaks.toml .

workflow-security:
	$(PYTHON) -I -c 'import sys;sys.path.insert(0,"tools");from local_scaffold.actionlint_view import main;sys.exit(main())'
	.venv/bin/zizmor --no-config --no-ignores --strict-collection --persona auditor --offline .github/workflows/*.yml

sbom:
	test ! -L .tool-cache
	test ! -L .tool-cache/sbom.json
	.venv/bin/cyclonedx-py environment --output-reproducible --output-format JSON --output-file .tool-cache/sbom.json $(PYTHON)

supply-chain:
	$(PYTHON) tools/check_source_provenance.py --root . --json
	$(PYTHON) tools/check_workflow_policy.py --root . --json
	$(PYTHON) tools/check_dependency_alignment.py --root . --json

PROVENANCE_INPUTS ?= .tool-cache/provenance-inputs
PROVENANCE_OUTPUT ?= .tool-cache/dependency-provenance.prospective.json
PROVENANCE_REFERENCE ?= dependency-provenance.json
PROVENANCE_ARTIFACTS ?=
PROVENANCE_OWNER_SOURCE ?=
PROVENANCE_SOURCE_ROOTS = $(if $(strip $(PROVENANCE_ARTIFACTS)),--artifacts "$(PROVENANCE_ARTIFACTS)") $(if $(strip $(PROVENANCE_OWNER_SOURCE)),--owner-source "$(PROVENANCE_OWNER_SOURCE)")
PROVENANCE_CAPTURE_SECONDS ?=

.PHONY: provenance-generate provenance-verify

provenance-generate:
	$(PYTHON) tools/reproduce_dependency_provenance.py --root . --inputs "$(PROVENANCE_INPUTS)" $(PROVENANCE_SOURCE_ROOTS) --mode generate --output "$(PROVENANCE_OUTPUT)" --json

provenance-verify:
	$(PYTHON) tools/reproduce_dependency_provenance.py --root . --inputs "$(PROVENANCE_INPUTS)" $(PROVENANCE_SOURCE_ROOTS) --reference "$(PROVENANCE_REFERENCE)" --json

.PHONY: prepare-provenance-inputs

prepare-provenance-inputs:
	$(PYTHON) tools/reproduce_dependency_provenance.py --root . --inputs "$(PROVENANCE_INPUTS)" $(PROVENANCE_SOURCE_ROOTS) --mode capture $(if $(strip $(PROVENANCE_CAPTURE_SECONDS)),--capture-seconds "$(PROVENANCE_CAPTURE_SECONDS)") --json
