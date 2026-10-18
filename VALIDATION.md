<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->
# Validation scope

The scaffold is being constructed. Its acceptance requires actual metadata/inventory, source provenance, workflow, dependency alignment, documentation and preflight commands; dedicated success/refusal/recovery tests; strict typing, lint and native documentation; licence and private-projection checks. A declared validator or required file is not a passed check.

Domain acceptance additionally requires real public writer/reader/capture/replay/slice boundaries, full byte and count preservation, deterministic logical replay, corruption location, exact index offsets, source-codec parsing, quota/cancellation and immutable partial recovery. Detached common evidence success does not establish capture or scientific acceptance.

No published coverage, performance, physical-clock or installed codec result is asserted during scaffold construction. Actual acceptance evidence determines when these statements change.


## Local command reference

Run these commands from the source root after <code>make environment</code>.
Use the project <code>.venv/bin/python</code>; the root argument supplies
inspected data rather than executable tool configuration.

| Operation | Command | Effect |
|---|---|---|
| Metadata | <code>.venv/bin/python tools/check_repository_metadata.py --root . --json</code> | Validate identity and lifecycle. |
| Inventory | <code>.venv/bin/python tools/check_repository_inventory.py --root . --mode verify --json</code> | Verify metadata and owned source inventory. |
| Provenance | <code>.venv/bin/python tools/check_source_provenance.py --root . --json</code> | Check actual public byte licences and provenance. |
| Workflows | <code>.venv/bin/python tools/check_workflow_policy.py --root . --json</code> | Validate the static workflow graph. |
| Dependencies | <code>.venv/bin/python tools/check_dependency_alignment.py --root . --json</code> | Read trusted audit admission without network renewal. |
| Documentation | <code>.venv/bin/python tools/check_documentation.py --root . --json</code> | Check source docs and render the strict site. |

There are four explicit metadata-writing operations:

| Operation | Command | Effect |
|---|---|---|
| Inventory generation | <code>make inventory-generate</code> | Create an inventory only at an absent destination. |
| Audit production | <code>make produce-audit</code> | Run the genuine producer and publish local audit admission. |
| Registry source capture | <code>make prepare-provenance-inputs</code> | Capture the complete fixed source cohort, or revalidate an existing complete snapshot offline. |
| Prospective provenance generation | <code>make provenance-generate</code> | Reconstruct all package/licence fields and publish a separate candidate. |

Capture uses a fixed installed worker under one inclusive process/cleanup
budget, default 120 seconds. Select a smaller positive finite budget through
<code>PROVENANCE_CAPTURE_SECONDS</code> or the capture-only CLI option
<code>--capture-seconds</code>. Timeout is unavailable; incomplete files remain
retained. Neither control applies to offline generation/comparison.

<code>make provenance-verify</code> performs read-only offline comparison.
Its default reference is the baseline, which can differ from later captured
responses. To compare a new candidate, select its exact path with
<code>PROVENANCE_REFERENCE</code>. Generation never adopts that candidate or
renews its retained historical audit declaration. The
[source workflow](docs/validation-tooling.md#offline-source-workflow) gives
the complete commands and source/output ownership.

None of these operations is an implicit repair fallback from verification.
Copying a foreign audit or editing its timestamp does not renew local admission.

Reports contain exactly <code>report_schema</code>, <code>gate</code>,
<code>scope</code>, <code>status</code>, <code>exit_code</code>,
<code>reasons</code> and <code>checks</code>. Exit 0 means the requested local
operation passed; 2 means refusal or output failure; 3 means unavailable or
interrupted; 4 means invalid invocation or configuration. A local diagnostic
does not grant domain, certification, publication or hardware acceptance.

The source-analysis and static-security Make targets run actual production
Bandit scanning. The configured python_security role has the same all-finding
policy, ignores inline nosec comments and uses a fixed empty INI source.
Preflight requires18roles; older17role reports cannot satisfy the complete
current plan. Its seven-field wire shape is unchanged. The three standalone provenance modes
do not add aggregate roles or imply that every role ran.

The complete preflight Make target includes the full test suite and belongs
to authorised CI or explicit pre-publication validation. Ordinary local work
uses the relevant commands and serial targeted tests. This reference does not
instruct a contributor to run the complete local plan.

Produce a current local security input with `make produce-audit`, then verify it
offline with `make dependency-security`. Production is explicit and restricted
to the actual trusted installation; an inspected repository cannot supply its
own admission store. The real producer test is
`python -m pytest -q tests/test_audit_producer.py`; it requires network access
to the existing vulnerability service and retains actual failures. The
[tooling guide](docs/validation-tooling.md) describes original-byte custody,
installation binding, freshness and the immutable historical source declaration.

The secret-scanner tests exercise the actual Make target, the configured native role and early public preflight refusal. They cover clean source, a detectable non-credential input, inline and fingerprint suppression, an absent producer and received suppression files or dangling links. Run this boundary with `python -m pytest -q tests/test_secret_scan.py`; it does not invoke the complete infrastructure test target.

Run `python -m pytest -q tests/test_sbom_publication.py` for the actual SBOM Make boundary. Its positive case verifies all 103 locked development components; cache-parent, output-file and dangling-output controls must refuse before unrelated data is changed or created. This is local tooling evidence and carries no release or deployment claim.

The SBOM target uses reproducible generation. Run
`.venv/bin/python -m pytest -q tests/test_sbom_reproducibility.py` for the
two-invocation byte comparison with the same installed inputs and no
`SOURCE_DATE_EPOCH`. [The tooling guide](docs/validation-tooling.md) describes
the generator inputs and scope.

Run `python -m pytest -q tests/test_audit_producer_completion.py` for real audit completion controls. The original cases interrupt the audit child after complete JSON output or change an isolated installation's source; both retain a refused attempt. Additional cases deliberately corrupt an owned output pipe and exercise an exhausted diagnostic budget with native interruption or a missing required input. They retain refused or unavailable terminal attempts, separate authentic auditor output from injected bytes and preserve the previous audit. These controls do not establish clean admission or whole-scaffold acceptance.

Run `python -m pytest -q tests/test_cli.py` for actual missing-producer, cleanup-denial and interruption controls. The full-budget case sends real SIGTERM after the final allowed diagnostic is recorded; it must retain native unavailability, the bounded report and every original input.


Current native Python collection covers tools and tests. Python outside these roots, hidden source path components and uppercase Python extensions refuse as scan_incomplete; adding a runtime, example root or new language requires complete native gate enrollment in the same change. Required Ruff lint, format and documentation checks ignore received Git exclusions: a received ignore rule cannot hide maintained source from those native roles, Make quality or the corresponding hooks.

Native source collection also refuses site-packages and an implementation shadowed by a same-stem Python stub until both populations have complete type qualification. Ruff exclusions match only the declared private cache directories; public dist, venv or build directory names cannot silently remove source from lint, format or documentation checks.

The parametrized tests/test_input_limits.py::test_actual_received_parent_substitution control uses the pinned native strace fixture to stop the public reader after a real lstat or directory open. It replaces the received root or nested parent with an owned symlink, resumes the same child and checks refusal or original-directory binding, descriptor cleanup and preservation of both source and outside bytes.
