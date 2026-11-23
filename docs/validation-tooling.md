<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->

# Validation tooling

## First local checks

The available commands check the repository scaffold. Recording and replay
remain planned. Start in the repository root on Linux with the locked
development environment described in CONTRIBUTING.md.

For a clean checkout, create the artifact directory with
`make fetch-environment-inputs`, or supply an independently selected one, and
select the Common owner source described in CONTRIBUTING.md; use CPython
3.13.18 as BASE_PYTHON. The fetch command is the one networked step: registry
artifacts come only over verified HTTPS from files.pythonhosted.org, any status
other than 200 is unavailable, the declared length and the bytes must equal the
pins, the local packages' wheels and records are copied from
vendor/environment-inputs, and a failure leaves no directory.
Run `make check-environment-inputs` with those selections before
`make environment`. Input checks precede every environment, cache, uv or builder
write. Artifact installation is offline and hash-required; no package-registry
fallback supplies missing local wheels.

The readiness command validates frozen project inputs and the original
package/source operands. Its report does not establish that an installed
environment satisfies the separately enrolled dependency profile. For an
existing environment, check its interpreter and then run these two commands
independently:

```sh
.venv/bin/python --version
.venv/bin/python tools/check_repository_metadata.py --root . --json
.venv/bin/python tools/check_repository_inventory.py --root . --mode verify --json
```

The first checks repository identity and the declared lifecycle. The second
also checks the existing capability inventory against that metadata. They
inspect local files and do not run the full test suite. Neither command
creates the inventory or installs a domain runtime.

A successful metadata check produces this seven-field report:

```json
{
  "checks": [],
  "exit_code": 0,
  "gate": "repository_metadata",
  "reasons": [],
  "report_schema": "spike_log.local-scaffold-guard-report.v1",
  "scope": "local_scaffold",
  "status": "passed"
}
```

The inventory check uses the same shape with `gate` set to
`repository_inventory`. Member order in JSON has no significance. `checks`
is empty for these leaf commands: it does not report execution of preflight
roles. Keep the process exit status as well as the report when recording a
result.

| Process exit | Report status | Interpretation |
|---|---|---|
| 0 | `passed` | This requested local check completed successfully. |
| 2 | `refused` | A checked requirement failed, or report output failed. |
| 3 | `unavailable` | Required input or tooling was unavailable, or work was interrupted. |
| 4 | `invalid` | Invocation or configuration was invalid. |

A report-output failure may leave no complete JSON record. Do not treat a
missing report or an empty `checks` list as successful execution of other
checks. A passing metadata or inventory check establishes only its declared
local scope; it does not qualify `.slog` files, capture, replay or hardware.

All eight public validation and provenance scripts accept `-h` or `--help`
without an available repository. Help is informational usage text with exit 0,
including when `--json` is present; it is not an operation report or evidence
that a check ran. Use complete long-option names: abbreviations such as `--roo`
are invalid for both the guard commands and provenance reconstruction.

The importable `main(arguments)` functions are CLI entry points and must run
on Python's main thread. They temporarily install a termination handler and
restore it before returning. Ordinary invocations return an exit integer;
`-h` or `--help` writes usage and raises `SystemExit(0)`. A call from another
thread raises `ValueError` before dispatch. Use child processes for background
validation.

For a documentation change, run the actual documentation entry point:

```sh
.venv/bin/python tools/check_documentation.py --root . --json
```

It checks maintained documentation and links, then builds the strict site.
Local link and image targets come from the rendered Markdown, including
reference-style links and authored HTML. Files and Markdown heading anchors
must exist. Literal link examples in inline code, fenced code and comments
are not destinations. External URLs are not fetched by this link check.
A successful render is documentation-build evidence; keyboard, focus and
screen-reader journeys require their own validation.

## Inventory generation and verification

Generate a prospective inventory at an unused output path whose parent exists:

```sh
.venv/bin/python tools/check_repository_inventory.py --root . --mode generate --output .tool-cache/capability-inventory.prospective.json --json
.venv/bin/python tools/check_repository_inventory.py --root . --mode verify --json
```

Generation checks the independent metadata, fixed schema, lock and installed
interpreter graph. It can run before the rest of the repository exists and
emits `inventory_generate` scope. Invalid metadata prevents publication;
an existing destination is refused without replacement.

Verification reads the canonical `capability-inventory.json`, checks its parsed
fields, and requires the complete tree and Git tracking rules. It does not
adopt the prospective cache output. The embedded metadata digest binds the
exact original metadata bytes. Generated capabilities, claims and qualified
schema IDs remain empty; generation success does not qualify the scaffold or
event-stream runtime.

## Other validation operations

Public guard commands are documented in `VALIDATION.md` in the source root. Each leaf emits the exact seven-field local diagnostic report. The aggregate requires18roles including actual production Bandit scanning. Received INI configuration and inline nosec comments cannot suppress required source findings. Inventory has separate generation and verification operations; preflight never generates or recursively invokes itself. The process API accepts explicitly trusted argument lists and qualifies only orchestration when tested with finite child programs.

`make quality` and the native documentation role enforce the full Ruff `D`
rules with the NumPy convention. `make test` defaults to serial execution
(`TEST_WORKERS=0`) at niceness 19. Allocated CI may set `TEST_WORKERS`
explicitly. The complete test and preflight targets belong to authorised
external validation; local changes use serial targeted public-boundary tests.
The required coverage gate measures both <code>tools</code> and <code>tests</code>,
with branches and a 100% floor. <code>TEST_SELECTION</code> selects an
authorised targeted test or cohort and <code>TEST_BASETEMP</code> selects its
owned temporary directory. Defaults remain the complete <code>tests</code>
tree and <code>.tool-cache/tests</code>. Selecting fewer tests preserves the
complete coverage denominator and floor: passing selected tests can therefore
still produce a failing coverage exit. Targeted pass counts do not establish
that the complete gate has passed.

`run_process` terminates and reaps only descendants that stay in the child's
original process group. Trusted commands must preserve that membership.
Session-escaping descendants require separate caller-owned cleanup. The Linux
subreaper flag remains enabled on the calling process after the operation;
unrelated children are outside the runner's wait and signal scope. See the
threat model for this execution boundary.

The synchronous `run_process` API requires a calling thread without an active
event loop. It refuses an active loop with `configuration_invalid` (exit 4)
before native setup, without starting a child or changing fresh observation
data. Another thread's running loop does not prevent synchronous execution in
a worker without its own active loop. The existing asynchronous `execute`
entry remains available to callers that own their async execution context.
The complete finite-plan consumer records this caller-context refusal as an
invalid outcome for each required role; it does not claim native tool execution.

An unexpected native failure records the current executed role as refused
(exit 2, `unexpected_fault`) and stops later children. Those later roles
remain `not_run`, so the complete report is unavailable (exit 3). Prior
role outcomes are preserved. A native child exit of zero does not pass
its role when the runner cannot certify process cleanup.

The native documentation configuration excludes private working documents and
assets from the generated site and search index. The documentation guard checks
the actual renderer output for private paths before accepting its native success.

The search dialog is named `Search`. The documentation guard accepts only the
exact maintained override and configuration, and renders captured copies.
Additional or changed executable templates are refused before rendering.

The metadata guard checks the accepted standard and profile digests independently of the generated inventory. The repository schema is also digest-bound; replacing it with an older or permissive schema is refused. Inventory generation records the exact metadata bytes only after metadata acceptance.

`docs/internal/` is private working state. Inventory checks its file kinds and
bounds and refuses tracked private paths; production-name inspection applies
to public files. A Git ignore rule does not excuse private bytes already in
the index.

The root `.gitignore` must contain both `docs/internal/` and
`docs/internal/**`; a leading `/` is accepted for either rule. Native Git
checks the effective directory rule with `--no-index`, including in a fresh
checkout where the private directory is absent. The effective match must be
the supported directory rule itself. A descendant-only match, negation or
other overriding pattern is refused as `repository_inventory.private-unignored`.
Git's verbose exit status alone does not establish exclusion. The separate
native index check still refuses tracked private and excluded build paths.

The public `context()` function measures the trusted tooling source, complete
installed producer metadata and interpreter identity. It supplies input for
local audit receipts. Calling it does not publish a receipt or grant audit
admission.

The dependency guard treats received TOML as data. A malformed document is
invalid configuration (exit 4); a parsed `tool` or `mypy` value that is not a
table is policy drift (exit 2, `dependency_alignment.hook-drift`). These refusals
preserve input bytes and do not echo received values or execute configuration.

The workflow leaf accepts one optional `--outcomes ROOT_RELATIVE_JSON_FILE`.
This bounded local JSON projection has exactly six flat string members:
`pre-commit`, `docs`, `codeql`, `security-audit`, `sbom`, `scorecard`.
Each value must be `success`, `failure`, `cancelled`, `skipped` or `not_run`.
The complete static graph is checked first; the supplied projection then passes
only when all six values are `success`. An admitted adverse input returns the
normal local report with exit 2 and `workflow_policy.aggregate-skipped`.
The no-input operation checks the static graph. Neither operation authenticates
a hosted run, and preflight does not accept the optional flag.

For example, place this projection in `.tool-cache/workflow-outcomes.json`
after creating its parent directory:

```json
{
  "pre-commit": "success",
  "docs": "success",
  "codeql": "success",
  "security-audit": "success",
  "sbom": "success",
  "scorecard": "success"
}
```

```sh
.venv/bin/python tools/check_workflow_policy.py --root . --outcomes .tool-cache/workflow-outcomes.json --json
```

The guard reads this file without changing it. The hosted `complete` job
receives GitHub's nested `needs` objects through `REQUIRED_RESULTS`; each
object has a `result` member. Its inline program requires exactly the same
six job names and rejects any result other than `success`. `not_run` is a
local projection status. Tests execute the unchanged inline program for all
4,096 combinations of GitHub's four job results; exactly the all-success
combination passes. This local execution does not establish a hosted result.

The [shared Python dispatcher](#local_scaffold.cli.main) documents the common
calling contract. Links between pages in `docs/` use anchors in the actual
MkDocs HTML output, including anchors supplied by mkdocstrings. Standalone
Markdown documents retain their source-heading checks.

The configured fragment extension normalises percent escapes for the
unreserved ASCII characters in local Markdown link fragments before native
anchor validation. Paths, queries, images, external URLs and reserved escapes
retain their spelling. Site anchor definitions use decoded characters;
percent-escape sequences belong in link fragments. Legacy named anchors use
`a` elements. Strict renderer validation remains enabled. The guard
checks the hook's complete source digest and captures it with the accepted
configuration and template before invoking the native renderer.

The public report consumer requires an explicit expected operation. Its default
is `local_scaffold`; it never chooses another scope from received report data.
The implemented scopes and their producers are:

| Scope | Expected producer |
| --- | --- |
| `local_scaffold` | The requested local validation guard |
| `inventory_generate` | `repository_inventory` |
| `audit_produce` | `dependency_alignment` |
| `provenance_inputs` | `provenance_reproduction` |
| `provenance_candidate` | `provenance_reproduction` |
| `provenance_comparison` | `provenance_reproduction` |

For example, pass `expected_scope="inventory_generate"` to `validate_child`
when consuming a generation CLI result. The expected producer and actual native
exit must still agree with the report. Admitting a diagnostic report confirms
its transport contract; the result retains the operation's declared scope.

::: local_scaffold.reports

::: local_scaffold.inputs

::: local_scaffold.processes

::: local_scaffold.metadata

::: local_scaffold.inventory

::: local_scaffold.inventory_tracking

::: local_scaffold.production_names

::: local_scaffold.provenance

::: local_scaffold.dependencies

::: local_scaffold.workflows

::: local_scaffold.documentation

::: local_scaffold.documentation_fragments

::: local_scaffold.orchestration

::: local_scaffold.cli

::: local_scaffold.actionlint_view

::: local_scaffold.security

::: local_scaffold.audit_context

::: local_scaffold.audit_store

::: local_scaffold.audit_records

::: local_scaffold.audit_producer

::: local_scaffold.yaml_inputs


The prepared workflow references use `$/.github/workflows/{filename}` on
github.com, as specified by the [GitHub workflow syntax reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_iduses).
GitHub Enterprise Server is outside this prepared profile. References bind
the caller commit and accept neither an explicit ref nor an expression.
This is checked locally; no hosted run or service configuration is inferred.

After `make environment`, run `make prepare-test-inputs` before tests on a clean checkout. It acquires the pinned native archives, CodeQL input, strace fixture and unsupported-patch interpreter, then runs the real strict dependency audit. The prepared test workflow uses this order. Acquisition uses the original HTTPS URLs and verifies the retained artifact digests.

`make produce-audit` invokes the existing dependency command with explicit
`--produce-audit`. Only the actual trusted tooling installation can produce;
an inspected foreign root refuses before any write or network call. The genuine
pinned pip-audit runs in isolation with a fresh private HTTP cache. Its original
bounded output, complete installed103 graph, metadata, source-policy digest,
interpreter and actual native completion time are retained in the private
`.tool-cache/security-admissions` store. Kernel leases prevent overlapping
production; a reader encountering a producer is unavailable. A pending HEAD
precedes production, immutable objects precede the terminal HEAD, and failed
or interrupted attempts cannot reuse an earlier clean HEAD as current success.

The ordinary dependency consumer is offline and read-only. Preflight does not
implicitly produce admission as a repair. Its complete test role can execute
explicit network-backed owning tests and is not a network-free operation.
The dependency guard compares received audit bytes with the independent latest clean local
receipt, enforce the original24hour lifetime and5minute future allowance, and
check every component and vulnerability. Source, graph, interpreter or
installation changes invalidate admission. A copied foreign store is not
automatically trusted locally. Missing, pending, interrupted and expired
admission is unavailable; findings and byte/source mismatch refuse. A real
fresh successful producer operation is required for renewal.

A clean receipt must identify the audit as the original complete stdout of
that producer attempt. Selecting a different retained capture is an invalid
receipt, even when both objects exist and their hashes are correct. Object
reads and producer destinations refuse links, FIFOs and wrong file kinds;
oversized HEADs and native write failures cannot become successful admission.

The original `security_audit` declaration in `dependency-provenance.json`
remains immutable historical source identity with an aware timestamp. Editing
that declaration refuses; its old time neither expires the new receipt nor
creates a new freshness window. This replaces the previous compiled audit-time
lifecycle. Local hashes and receipts supply software-account integrity and
correspondence, not signatures, remote attestation or physical custody.

The POSIX publication tests use the pinned Ubuntu strace 6.8 fixture on Linux amd64. `make prepare-test-fixtures` prepares that fixture independently. Preparation verifies the package, executable and original third-party copyright; `dpkg-deb` extracts into the repository cache without installing a host package. The fixture traces only its own child processes and exercises real syscall errors and interruption boundaries. A missing fixture is unavailable, and cannot yield a passing test result.

The retained dependency-refusal cache was constructed from the original103-producer graph. It cannot qualify the106-producer profile until its actual native input preparation and complete readback are migrated. A qualified cache avoids copying that environment on every run. Each use verifies the interpreter, complete installed versions and original METADATA digests. Exclusive locks protect intentional producer changes, and each case restores and rechecks the complete graph. An incomplete or changed cache remains a failure; the tests preserve it for inspection.

Run `make prepare-interpreter-fixture` for the genuine unsupported-patch case. It first runs `make prepare-test-wheels`, which prepares the verified packaging, coverage and PyYAML artifacts. Its independently pinned CPython 3.13.15 archive and copied executable exercise refusal below the reviewed `>=3.13.18,<3.14` range. The isolated environment contains only the two real producers needed for that early boundary: packaging and coverage, both installed from verified wheel bytes. The dependency guard refuses the actual interpreter before treating missing package producers as an availability problem.

`make prepare-major-interpreter-fixture` prepares the independently pinned
CPython 3.14.7 artifact and its genuine coverage wheel. The metadata and
dependency tests exercise this actual unsupported major version as well as
the older patch version. Each isolated interpreter has exactly packaging and
coverage with the original producer metadata. `make prepare-test-inputs`
prepares both interpreters; their presence does not extend the supported range.

The provenance guard uses isolated Python module discovery for its real REUSE
producer. Received modules or packages with the producer's name remain data;
the checker never imports them from the inspected repository.


`analyse_reuse` preserves every public relative path and byte in a temporary
licence-check tree. It runs the installed REUSE CLI, including global and nested
licensing and unused-licence checks, then verifies both the original and copied
inputs. Received Git ignore rules cannot suppress public files. Cached and
private inputs remain outside the existing public ownership scope. All stages
share the unchanged inclusive 120-second limit.

The temporary tree respects the caller's `TMPDIR`, `TMP` and `TEMP` settings.
Git discovery for the native licence producer stops at the temporary parent,
so an ignored workspace inside another repository cannot conceal its inputs.
The absolute isolated Python producer also receives a closed executable search
path. Native licence discovery cannot select received programs through the
caller's `PATH`; the caller's environment remains unchanged. Original producer
code, licence rules, source bytes and native findings remain in force.

The native secret scanner uses the received repository as its working directory and scans relative input paths. Cache exclusions apply within that repository; an ancestor cache directory cannot hide its public source. The scanner executable and configuration remain bound to the trusted implementation. The dedicated secret-scan tests exercise the actual Make target, suppressed-input refusals, missing-producer failure and the configured native role.

Received `.gitleaksignore` files, including dangling symbolic links, are refused before a required scan. The Make target and preflight enforce this boundary because the pinned native scanner also reads suppression files from its input directory. Inline suppression comments cannot silence the required scanner.

The SBOM Make target writes the actual installed development graph to
`.tool-cache/sbom.json` using the generator's `--output-reproducible` mode.
Repeated runs with the same installed environment and generation inputs
produce identical bytes. If `SOURCE_DATE_EPOCH` is supplied, it is an input
to the timestamp; without it, volatile time and random values are omitted.
Changing the environment, generator version or epoch changes the inputs and
may change the result.

Run `.venv/bin/python -m pytest -q tests/test_sbom_reproducibility.py` to
exercise two real Make invocations without an epoch and compare their complete
output bytes. This complements the existing complete-component test; it does
not qualify a package or release.

The target refuses symbolic links at the cache directory or output file,
including dangling output links, before invoking the producer. The dedicated
publication tests retain that boundary's existing acceptance scope.

The sparse-tool availability fixture installs exactly packaging, coverage and PyYAML from the verified wheel cache. `make prepare-test-wheels` downloads a missing original artifact through its pinned HTTPS URL and checks every wheel digest, including existing cached files. Symbolic wheel paths and corrupt cached bytes are refused. This prepares an intentionally incomplete graph for refusal tests; it does not qualify that graph as the complete development environment.


The dedicated tests/test_static_security.py boundary runs actual Make and the configured native scanner on clean source and a known assert finding, including inline/receivedINI suppression attempts. Its public finite-plan case uses genuine configuredBandit and17explicit harmless children solely for orchestration; this does not execute or qualify the other native tools.


Current native Python collection covers tools, tests and the enrolled src/spike_log namespace. The exact empty py.typed marker is data and has its own ownership notice. Python outside those roots, hidden source path components and uppercase Python extensions refuse as scan_incomplete; adding another runtime, example root or language requires native gate enrollment in the same change. Required Ruff lint, format and documentation checks ignore received Git exclusions: a received ignore rule cannot hide maintained source from those native roles, Make quality or the corresponding hooks.

The inventory and dependency checks use the same exact reviewed Poetry builder, project metadata, source package and typed-marker includes. Extra package files, dependencies, altered namespaces/build hooks and private include paths remain refused. This source/configuration check is separate from actual wheel-content and installed-consumer checks, full native qualification, release and publication.

The native dependency audit queries the fixed OSV endpoint and requests every advisory identifier, alias and available fix version without long prose descriptions. Private version-two receipts record that source, endpoint and actual query interval. OSV supplies no global database revision, so receipts leave it unavailable rather than claiming a database snapshot. Historical version-one receipts remain stored and cannot supply current admission. The fixed capture limit and all finding checks remain in force. An adverse or incomplete audit refuses admission; packaging acceptance does not override its result.

Native source collection also refuses site-packages and an implementation shadowed by a same-stem Python stub until both populations have complete type qualification. Ruff exclusions match only the declared private cache directories; public dist, venv or build directory names cannot silently remove source from lint, format or documentation checks.

## Offline source workflow

The public entry point is `tools/reproduce_dependency_provenance.py`. It has
three explicit modes: `capture` prepares source bytes, `generate` publishes
a prospective manifest, and `verify` compares without writing. These are
repository-tooling operations, separate from planned event-stream capture.

From a fresh locked environment, use:

```sh
make prepare-provenance-inputs
make provenance-generate
make provenance-verify PROVENANCE_REFERENCE=.tool-cache/dependency-provenance.prospective.json
```

Generation requires a new output path. For another candidate choose
`PROVENANCE_OUTPUT` and pass that same path as `PROVENANCE_REFERENCE` for
comparison. Do not remove an earlier candidate merely to rerun the example.
Capture needs a repository-relative destination whose parent already exists.
Generate/verify accept an explicit existing input snapshot; capture is the
only mode that fetches registry responses.

### Offline reconstruction

Supply a complete preserved source snapshot explicitly. Its inputs.json has
input_schema spike_log.dependency-source-inputs.v2 (v1 admits no owner-source
response), the exact interpreter version, accepted full-lock digest and one
record per graph package.
Each record has canonical name, exact version, relative response path and
SHA-256 of the complete raw response. Preserve those response files beside
the index. A later same-version response is a different source when bytes differ.

```sh
make provenance-generate PROVENANCE_INPUTS=.tool-cache/provenance-inputs PROVENANCE_OUTPUT=.tool-cache/dependency-provenance.prospective.json
make provenance-verify PROVENANCE_INPUTS=.tool-cache/provenance-inputs PROVENANCE_REFERENCE=.tool-cache/dependency-provenance.prospective.json
```

Generation needs a new output path and never replaces an existing file.
Verification reads its reference and never fetches data or adopts a candidate.
Omitting PROVENANCE_REFERENCE compares against dependency-provenance.json and
refuses when reconstruction differs. Successful candidate comparison proves
only reconstruction from supplied bytes and the actual installed environment.
It establishes neither historical reconstruction nor trusted audit admission
or adoption of changed source bindings.

The candidate includes every installed package record with ordered metadata,
every declared licence-file selection and the selected source-artifact descriptors.
Its metadata_sha256 identifies UTF-8-encoded native Distribution.read_text
output, including filesystem text-mode newline normalisation. Registry-response
and declared licence-file hashes identify the original raw bytes.
Native/historical declarations remain authored inputs, not new producer results.

The provenance_reproduction report has scope provenance_candidate for
generation and provenance_comparison for verification; checks remains empty.
Missing input is unavailable, inconsistent identity refuses, invalid options
remain invalid. Neither operation runs a security audit.

Dedicated tests use the complete genuine snapshot that the repository tracks at
`vendor/provenance-inputs`, or another selected by SPIKE_LOG_PROVENANCE_INPUTS.
It holds the original registry responses whose digests the provenance pins,
and the two owner-source response records. Missing or changed bytes fail; no
skip or substitute fixture. Its registry responses are third-party metadata
under `LicenseRef-PyPI-Metadata`, and the inventory and source-provenance
checks admit each one only by the digest the provenance pins.

::: local_scaffold.provenance_sources

::: local_scaffold.provenance_reproduction

::: local_scaffold.provenance_cli


### Prepare a complete prospective source snapshot

From the installed hash-locked environment, run:

```sh
make prepare-provenance-inputs
make provenance-generate
```

The first command captures each registry package's full version-metadata
response from PyPI and copies each owner-source package's response record from
PROVENANCE_ARTIFACTS, which it validates against PROVENANCE_OWNER_SOURCE,
validates their selected source artifacts against the baseline, and records raw
byte hashes in `inputs.json`. `make prepare-test-inputs` now includes this step.
Generation and comparison remain offline. Existing complete snapshots are
revalidated offline and retained; no command silently refreshes them.

The standalone `package_record` API checks that the native distribution version
matches the selected original record before copying its metadata fields. A
different version produces `source_identity_mismatch`; absent metadata retains
the existing `dependency_alignment.wrong-producer` refusal. The complete CLI
also checks the full installed graph before reconstruction.

Run `make prepare-provenance-identity-fixture` to prepare the genuine older wheel
used by the focused identity tests. It is metadata test data and is not installed
into the development environment. `make prepare-test-inputs` includes this step.

Capture mode accepts a repository-relative `--inputs` directory. Each response
uses the existing input cap of 1 MiB and a socket timeout of 10 seconds. The parent runs
the fixed installed capture worker through the existing bounded process runner.
Its default budget of 120 seconds includes worker startup, repository and installed
source validation, response acquisition, publication, complete snapshot readback
and owned process-group cleanup. It reserves cleanup time within that budget;
it does not promise 120 seconds of network acquisition or a hard real-time host
guarantee. The index is published after every response succeeds.

Use `--capture-seconds` for a smaller positive finite budget at most 120 seconds.
The Make equivalent is:

```sh
make prepare-provenance-inputs PROVENANCE_CAPTURE_SECONDS=60
```

The option applies only to capture, including offline validation of an existing
complete cohort. Generate and verify reject it. Zero, negative, nonnumeric,
nonfinite, duplicate and over-ceiling requests are invalid. An expired operation
reports unavailable with `tool_timeout`; partial files are retained and an
unobserved completion cannot pass. A later invocation can independently validate
a complete existing cohort without changing the previous attempt's outcome.
An incomplete directory is retained and refused; select a new directory for a
new attempt. A successful `provenance_inputs` report means that the snapshot was
prepared, not that an audit or numerical qualification passed.

A newly captured response may differ from the original historical response
for the same package version. Preserve both identities; capture does not
reconstruct missing historical bytes or alter `dependency-provenance.json`.

::: local_scaffold.provenance_capture

::: local_scaffold.provenance_capture_worker

Capture and reconstruction also require the reviewed exact `requirements-dev.in`
bytes used by the fixed lock. A changed, removed or additional direct declaration
refuses before a candidate or capture directory is created. Direct-input changes
need their lock, provenance and source bindings reviewed together.


## Local wheel source records

The independently bound provenance baseline selects a local source with
`source_kind` equal to `first_party_wheel` or `maintained_wheel`. These records
carry no invented `official_metadata_sha256` or publisher URL. They retain
actual native metadata, requirements and complete selected licence files,
the exact wheel descriptor, the source-input digest, and pinned owner/build
evidence. Historical `owner_work_in_progress` records retain their source-only
meaning. The current `committed` record additionally requires a complete pinned
manifest with the actual native owner commit and tree, every tracked blob and a
clean owner checkout. Source equality does not establish successful build execution
or security admission.

Mixed prepared snapshots use `spike_log.dependency-source-inputs.v2` with the
same complete independently selected graph, interpreter and lock bindings.
The original v1 registry snapshots remain registry-only. Neither version
changes the expected graph or admits another installed distribution.

The command accepts `--artifacts` for the explicit input-file root and
`--owner-source` for the owning source tree. Make forwards these as
`PROVENANCE_ARTIFACTS` and `PROVENANCE_OWNER_SOURCE`. Descriptor paths select
bounded input bytes, never executable callbacks, imports or network locations.
A missing local wheel/source refuses; capture cannot create a new mixed
cohort by looking up an unpublished development version on PyPI. Capture can
revalidate an already complete prepared cohort under its inclusive deadline.

Local reconstruction checks the original archive digest, complete safe ZIP
population, every RECORD size/hash, native installed member bytes, metadata,
package file population, owner source manifest, selected build evidence and
licences. A first-party wheel's product files must equal its declared source
population. Both namespace roots and their entries refuse symbolic links;
missing or inaccessible directories remain unavailable. ZIP member identity
includes a comparison of the original METADATA bytes with the installed member.
Declared licence members must actually exist in the verified wheel.
Package directory names are selected independently from distribution names:
a distribution name alone does not define its import namespace. ZIP directories
must be empty structural entries with safe names and directory mode; they count
towards the entry limit but are not files in RECORD. Nonempty directories and
symbolic or special archive entries refuse.
The maintained Metadata-Version 2.1 branch checks its explicitly
selected LICENSE and NOTICE without inventing absent License-File headers.
Source correspondence remains separate from runtime admission and the
independent maintained-fork/upstream security review.

### Original inputs for local source tests

The local source tests require the actual Common and maintained RFC distributions
in the test interpreter, their original wheels, the owner's complete source
manifest and source tree, and the original build evidence. Missing originals
remain a test failure. The test suite does not substitute a registry release for
an unpublished wheel or create a passing source record from sample package code.

For `make test`, set `LOCAL_SOURCE_ARTIFACTS`, `LOCAL_SOURCE_INPUTS` and
`LOCAL_SOURCE_OWNER` when the supplied inputs use other locations. They default
to the repository root and `.tool-cache/environment-inputs`. The owner
source is explicitly selected by `ENVIRONMENT_OWNER_SOURCE` or
`LOCAL_SOURCE_OWNER`; it is never inferred from received inputs. Keep the supplied input files and
`TEST_BASETEMP` beneath `LOCAL_SOURCE_ARTIFACTS`; the owner tree is selected
separately. Direct pytest invocation uses the corresponding environment
variables `SPIKE_LOG_TEST_ARTIFACTS`, `SPIKE_LOG_TEST_LOCAL_INPUTS` and
`SPIKE_LOG_TEST_OWNER_SOURCE`.

The input directory preserves these original bytes under portable leaf names:

| Leaf | Required original |
| --- | --- |
| `evidence_manifest_toolkit-0.0.0.dev0-py3-none-any.whl` | Common wheel, SHA-256 `b4ade75b41bcdf0126e5ea1fb2ce96fddc5a99ab738a822ddc0e7fbf119ccb72` |
| `rfc8785-0.1.4+emt.1-py3-none-any.whl` | Maintained fork wheel, SHA-256 `e04761706fcbbb5f0afd5fa74a7e6ea7484ce97f073adb5372ab8ee93230c48e` |
| `owner-source-inputs.json` | Complete original source manifest, with paths relative to the separately selected owner tree |
| `common-build-producer.json` | Original Common build producer profile |
| `common-wheel-source-identity.json` | Original Common wheel and source identity evidence |
| `common-sdist-rebuild-identity.json` | Original Common source-distribution rebuild identity evidence |
| `rfc8785-source-provenance.json` | Original maintained-fork source provenance |

Every hosted job that installs the environment checks out the owner repository
at the pinned Common commit into `.tool-cache/owner-source` and selects it as
`ENVIRONMENT_OWNER_SOURCE`; the infrastructure tests also give it to the
provenance capture, with `vendor/provenance-inputs` as the snapshot.

The repository tracks this input set under `vendor/environment-inputs`. Renaming a retained original for
transport leaves its content unchanged. Availability of owner-approved source
and artifacts in a hosted runner is a separate requirement from local test
success; neither passing these tests nor providing the files approves owner work
in progress or establishes current security or scientific admission.

::: local_scaffold.provenance_local

::: local_scaffold.provenance_wheels

Registry capture contacts the fixed pypi.org TLS origin and requires HTTP 200.
Redirects and other statuses remain unavailable; they do not select another
scheme, host or metadata source. Connections close on success and failure,
while the existing inclusive capture deadline and raw-response bounds remain.


## Environment input readiness

The stdlib-only `tools/check_environment_inputs.py` command runs before the
development environment exists. Its required data arguments are `--artifacts`,
`--owner-source` and `--environment`. `--root` selects inspected project data;
it never selects executable modules. `--max-input-bytes` is a positive integer
no greater than 134217728. `--json` selects the standard seven-field diagnostic.
Unknown, abbreviated, missing or malformed arguments are invalid without
echoing received values. This bootstrap command is separate from the eight
installed validation/provenance scripts and does not add a preflight role.

The independently frozen project identities cover requirements-dev.in,
requirements-dev.txt, requirements-runtime.txt and dependency-provenance.json.
Every selected package artifact is checked for its original size and SHA-256.
The local package response files are `evidence-manifest-toolkit.json` and
`rfc8785.json`. Their manifest and build-input paths are data beneath the
artifact root; the separately supplied owner tree must match the manifest's
actual files. Names and identities come from the frozen source selection,
rather than an inferred distribution namespace or a guessed publisher URL.

An absent destination or an existing empty directory can pass. An existing
environment must identify the same CPython interpreter, exact version and
disabled system site packages. Linked paths, overlap with either input tree,
unrelated nonempty directories and incompatible existing environments refuse.
The check does not execute the inspected destination interpreter.

Reads share one cumulative byte budget across project files, artifacts,
responses, manifests, source files, build inputs and any existing environment
configuration. The same admitted owner manifest is checked against its source
tree once per operation; its repeated references do not reset that budget.
All per-input and whole-operation ceilings remain fixed.

`make environment` reaches the same check through `make prepare-uv`.
Both stop before writes for an absent or corrupt selected wheel, including
Common and the maintained RFC wheel. After readiness the existing bootstrap
verifies the extracted uv binary, uses only the explicit artifact directory
for hash-required installation, and runs the native dependency check.
Readiness is not whole source, owner commit, vulnerability, installed graph,
domain runtime or scientific acceptance.

The owning `tests/test_environment_inputs.py` exercises real original inputs,
the public API/CLI and actual Make commands. It checks unchanged destination
trees on both successful reads and refusals. For a targeted run, supply
SPIKE_LOG_TEST_LOCAL_INPUTS and SPIKE_LOG_TEST_OWNER_SOURCE as described under
local source fixtures, plus SPIKE_LOG_TEST_ENVIRONMENT_SOURCE containing the
four exact frozen project inputs. SPIKE_LOG_TEST_ARTIFACTS retains its existing
artifact-root meaning. Missing required originals remain failures.


## Committed local producer qualification

The current environment contains 106 producers. The native advisory query contains
the exact 104 registry packages; Common and the maintained RFC wheel remain
separately bound local sources, with independent source security review. The
current receipt binds every one of the 106 installed metadata bodies and the
registry graph. A local package is never assigned a fabricated registry clean row.

Supply the complete flat original input directory at
`.tool-cache/environment-inputs`. The dependency guard validates both local
wheel digests, their exact lock hashes, complete RECORD and actual installed
member bytes from this trusted cache. It refuses a WIP local source. Explicit
source reproduction still requires `--artifacts` and `--owner-source`;
those roots never come from received descriptors. Committed reproduction reads
the complete native Git tree under a shared deadline, disables executable
callbacks and replacement objects, and checks every verified original source
byte against the selected commit. Missing, dirty, moved, partial or altered
source refuses. A committed label alone supplies no authority.

::: local_scaffold.committed_source

::: local_scaffold.local_dependencies
