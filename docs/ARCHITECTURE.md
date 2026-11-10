<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->
# Container data flow

The immutable capture plan precedes container bytes; final run results are later objects. Header, chunks, exact index offsets and footer are checked as a whole, with the seal detached. A corruption report locates the damaged region and refuses complete verification.

Source-native side bytes retain their codec identity and complete source population. Unknown codecs can be archived without claiming interpreted semantics. Replay requests preserve logical event content; achieved timing is separately observed. Slicing creates a new content identity with retained source provenance.

The repository does not convert third-party formats, judge event quality, synthesise ground truth or implement capture hardware. Those boundaries remain with the owning tools.

## Native payload codecs

The public Python package owns the two fixed binary payload contracts.
Canonical DVS columns keep unsigned16 image addresses and an explicit polarity
convention; logical source records keep unsigned64 population-scoped identities.
Both preserve original signed ticks, occurrence order and duplicates, reject
coercion/overflow, and require explicit finite batch quotas. The complete
container reader/writer and source/current verification consume these formats
under their own admission contracts. See [native API](native-payloads.md).

## Native integrity preimages

The public container digest operations implement the fixed header, timed-chunk,
metadata-chunk, chain and index preimages. Header and individual index rows use
Common canonicalization; the complete outer transport is still raw bytes.
Index hashing consumes bounded rows once with shared cumulative byte/count
limits. Component hashing is distinct from whole-container parsing, source
admission, exact offset checking and detached Common verification.

## Repository validation

The implemented tooling validates a received repository as data. Its fixed
CLI dispatch and native producers come from the executing trusted installation.
A received Python module, template, YAML file or tool setting cannot select an
executable command or replace that installation's audit admission.

| Component | Current responsibility | Boundary |
|---|---|---|
| Public guard scripts and cli | Dispatch metadata, provenance, workflow, dependency, documentation and inventory verification; emit the closed local report. | Invalid invocation and interrupted or incomplete work retain their actual failure status. |
| inputs, yaml_inputs, inventory, inventory_tracking, production_names | Bound file kinds, paths, bytes and structures; inspect maintained source with native parsers and actual Git rules/index. | Received source is inspected without importing or executing it. Unsupported collection remains unqualified. |
| metadata, dependencies, policy | Check repository identity, the fixed lifecycle/schema/profile, locked producers and native configuration. | Architecture-only metadata retains empty domain capabilities and qualified schema inventories. |
| processes, orchestration, actionlint_view | Run trusted argument lists with bounded captures, shared deadlines and owned process-group cleanup; preserve every required role outcome. | The caller-supplied root selects inspected data, not test programs or producer plugins. |
| provenance, documentation | Check original public byte licences and build captured, fixed renderer inputs. | Received templates cannot replace executable renderer configuration; private working files stay outside the public projection. |
| audit_context, audit_records, audit_store, security | Bind and consume the latest genuine audit admission for this installation. | A received audit, hash or timestamp cannot create or renew local trust. |
| audit_producer and inventory generation | Publish audit admissions and a new capability inventory. | Both are explicit operations; neither is a verification fallback. |
| provenance_cli, provenance_capture, provenance_capture_worker, provenance_reproduction, provenance_sources | Capture the fixed registry cohort, reconstruct a prospective manifest or compare it offline. | Inputs, candidate publication and comparison have separate report scopes and never renew audit admission. |

The six read guards leave received source unchanged. Native producers can use
their fixed private caches, temporary licence/rendering views and diagnostic
outputs. The complete configured preflight adds the native quality, security,
test, licence and inventory roles; its test suite is reserved for the authorised
validation stage described in the [tooling guide](validation-tooling.md).

### Commands, data and publication ownership

| Operation | Source of computation | Inputs and outputs |
|---|---|---|
| Six read guards | Fixed executing installation and reviewed native producers | Inspect the received repository; preserve its source; emit local diagnostics. |
| Inventory generation | `inventory` after repository metadata validation | Publish a new capability inventory at an absent root-relative destination. |
| Audit production | `audit_producer` in the actual trusted installation | Read the current installed graph/source policy and publish private pending/terminal admissions and original auditor objects. |
| Source capture | `provenance_capture` supervises the installed `provenance_capture_worker`, explicitly selected through `provenance_cli` | Fetch the baseline-selected PyPI version responses into a new root-relative snapshot; retain or revalidate an existing cohort as described below. |
| Prospective generation | `provenance_reproduction` using `provenance_sources` | Read an explicit complete snapshot and installed producer/licence bytes; publish a separate candidate at an absent root-relative destination. |
| Provenance comparison | The same offline reconstruction followed by object comparison | Read an explicit snapshot and reference manifest; emit a comparison result without publication or adoption. |

The reviewed direct-input bytes, complete development lock and original
provenance baseline have fixed identities in the executing policy. An inspected
root cannot replace those expected identities. The installed interpreter,
native METADATA text, dependency/classifier ordering and selected licence bytes
come from the executing environment. METADATA identities hash the UTF-8 encoding
of Distribution.read_text output, with filesystem text-mode newline normalisation.
The snapshot supplies original registry response
bytes and the baseline selects source artifacts. All106package records and
165declared licence-file selections participate.

### Four explicit metadata-writing operations

Inventory generation first validates metadata and builds the initial empty
capability inventory from those exact bytes. The shared `inventory.publish`
primitive writes and syncs a new sibling temporary file, then publishes through
an exclusive hard link. Existing destinations are refused. A complete output
published before a later durability failure remains evidence.

Audit production checks the actual installed graph and source policy, takes
an exclusive kernel lease and publishes a pending admission before invoking
the fixed genuine auditor. Original stdout/stderr are immutable digest objects;
a terminal receipt binds actual completion, graph, interpreter, source and
installation. A failed or interrupted attempt cannot reuse an older clean
admission as the latest success.

Source capture validates metadata, baseline and direct-input identity before
creating its chosen directory. The destination parent must already exist.
The fixed baseline determines104registry package/version URLs and two closed
local wheel/source branches. Local packages require independently supplied
original artifacts and owner inputs; no publisher URL or registry fallback is
invented for them. Received responses select neither executable programs nor
additional downloads. Capture checks each response
and selected artifact, retains exact raw bytes and hashes, then publishes
`inputs.json` last. A directory without a complete accepted index remains
incomplete and is retained. A caller chooses a new path for a new attempt.
An existing complete cohort is checked offline without a refresh.

The parent chooses the installed interpreter, fixed worker program, module path
and working directory. The inspected root and snapshot path remain worker
arguments. The same runner supervises the complete operation, including existing
snapshot validation and cleanup, under a positive finite budget at most 120 seconds.
`--capture-seconds` and Make's `PROVENANCE_CAPTURE_SECONDS` select a smaller
capture-only budget; offline generate/verify remain separate.

The worker emits only its bounded operation report; raw registry bytes stay in
snapshot files under the existing response cap. The parent admits the actual
native exit and complete report using the explicit `provenance_reproduction`
gate and `provenance_inputs` scope. The shared child validator still defaults
to `local_scaffold`; no aggregate role implicitly accepts a snapshot result.

Prospective generation loads a complete explicit cohort and reconstructs all
package fields from that cohort and installed producer bytes. It preserves
authored native/historical declarations and original record ordering, then
uses the same exclusive publication primitive for a separate manifest.
It never overwrites `dependency-provenance.json` or updates the expected hashes.

A registry snapshot taken later may have different complete response bytes
for the same version. Such a candidate can reproduce its supplied inputs
without reproducing the original historical source. Its retained audit
declaration is not a newly executed audit. Adoption of changed lock/provenance
bindings remains a separate reviewed change.

### Read operations and execution scope

The offline dependency consumer holds a shared admission lease, validates the
latest receipt and original objects, compares received audit bytes, and applies
freshness and complete-graph rules. It never starts an auditor or renews time.

Provenance comparison reconstructs from the caller's explicit cohort and
compares with the selected reference, defaulting to the current baseline.
It neither captures new responses nor accepts its own candidate as adopted
source. A mismatch remains a refusal. The command's scopes are
`provenance_inputs`, `provenance_candidate` and `provenance_comparison`;
each leaf keeps an empty `checks` list.

The existing aggregate retains its eighteen required roles. Capture, candidate
generation and comparison are explicit standalone operations, not additional
aggregate roles or automatic repairs. Their maintained code is enrolled in
the existing native type/lint/doc/test source populations. Test preparation
now calls `make prepare-provenance-inputs`; the full test role can execute
explicit owning network tests. The complete aggregate is therefore not a
promise of network-free execution.

Audit-store leases govern actual audit admission. Snapshot/candidate hashes
and exclusive publication do not authenticate the local administrator, make
a directory an immutable store or qualify a scientific result.

### Planned container integration

The recording/replay writer, independent container reader, capture adapters
and container CLI remain planned. Their future seals consume genuine shared
evidence primitives; the existing local guard reports are a different contract.
The current tooling implements no format converter, capture hardware, physical
timing guarantee or numerical model qualification.

Bounded input reads resolve the absolute filesystem anchor and every directory through held no-follow descriptors. The final regular file is opened relative to the held parent. Descriptor ownership closes in reverse order on success or refusal, preserving the lexical diagnostics and byte caps. Parent replacement cannot redirect that read to a new symlink target.
