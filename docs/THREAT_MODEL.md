<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->
# Threat model

Assets are original ordered event/source bytes, immutable capture plans, container/index/chain identities, source-codec metadata and reproducibility reports. Trust boundaries include received files, capture adapters, local storage, configured resolvers and detached evidence sources.

Malformed lengths, duplicate keys, invalid Unicode, integer range errors, unknown schema/codec, forged counts, path escape, symlink substitution, resource exhaustion, reordered data and altered index/chain bytes must refuse the affected operation. Received metadata never chooses executable code or a trust root.

Partial recovery preserves located gaps and original failed bytes. It cannot claim complete input coverage. A detached signature proves only its actual qualified target and class; it does not qualify a source clock, unknown codec or neural model. Physical capture and external producer provenance require their actual owning acceptance evidence.

No security assessment or implemented mitigation is claimed solely from this document. Runtime tests and appropriate independent review must exercise the real boundary before acceptance.

## Repository tooling execution boundary

The scaffold guards read received files as bounded data. Received YAML, source, templates and metadata cannot choose a native producer or executed configuration. Fixed tool bytes and closed configuration are checked separately. Actual source provenance uses unchanged native REUSE over an original-byte public projection; documentation uses a captured fixed renderer configuration and template with static source inspection. These are software-account checks and do not establish protected physical custody.

Explicit audit production writes only the executing trusted installation's
private admission store. Offline consumers cannot run the producer, refresh
time from received data or select another store. Admission binds the actual
installed graph, source policy, interpreter and installation namespace; an
unmodified foreign receipt does not qualify this installation. A writer that
controls the trusted implementation/account can also rewrite the checker.
Object hashes and local kernel leases do not authenticate such a writer or
provide remote attestation. Failed/pending production and unavailable current
receipts remain failures rather than falling back to historical clean data.

The trusted process runner terminates and reaps descendants only within the original child process group. Trusted commands must preserve that membership; a session-escaping descendant needs separate caller-owned cleanup. The Linux subreaper flag remains enabled after the call, while unrelated children remain outside its wait/signal scope. Bounded captures, deadlines and missing-producer refusals apply independently; a successful parser or process does not qualify domain semantics.

The required secret scanner interprets paths relative to the received repository. Cache exclusions cannot hide public files merely because an ancestor directory is a cache. Received `.gitleaksignore` files and dangling links are refused before any preflight child runs; inline suppression comments cannot select a weaker scanning policy. The native executable and authored configuration retain their trusted source identities.

Local SBOM generation must not follow a cache-directory or output-file symbolic link into unrelated data. The Make entrypoint rejects these links before invoking the native producer; the configured preflight separately validates its trusted output paths. Successful component enumeration does not establish an attestation or deployment qualification.

## Source collection and fixed configuration

Required Python quality collection covers the admitted tools and tests
roots. Out-of-root, hidden, case-mismatched, native-skipped and stub-shadowed
implementation populations cannot silently obtain complete collection.
Introducing a runtime, language or generated interface requires matching native
gate enrollment. Unknown inspected language surfaces remain unqualified.

Received Git exclusions cannot hide source from required Ruff lint, format or
documentation checks. Native Ruff exclusions use the same declared private
cache directory names as the inventory boundary. A sibling-interface probe does
not follow a received symbolic link. These controls preserve the admitted
source population; passing them does not establish its application semantics.

The inspected root does not select producer programs, plugins, test imports or
renderer configuration. Temporary views and native output paths belong to the
trusted operation. A party that controls that installation or account can also
change its fixed policy; local hashes and process leases do not provide a
sandbox or remote attestation against that party.

Received-file reads hold every parent directory open and open each subsequent component relative to its descriptor with O_NOFOLLOW. A parent replaced by a symbolic link before it is opened is refused; substitution after opening retains the original directory binding. The final input is opened nonblocking with O_NOFOLLOW, checked as a regular file and bounded both before and after reading. These checks prevent pathname redirection through replaced parents; they do not provide a snapshot against in-place changes to an admitted regular file.


## Registry snapshots and prospective manifests

Registry capture is an explicit network operation for the hash-bound baseline's
fixed package/version cohort. It retains raw responses and publishes its index
last. A complete existing cohort is revalidated offline; an incomplete cohort
remains unavailable and is retained. Capture is not a source of audit admission.

The installed parent chooses the worker program and interpreter. Received root
and snapshot names are data arguments. The original process budget covers
validation, acquisition, publication, readback and owned cleanup; timeout or
missing terminal outcome cannot pass. Raw responses are files, while worker
stdout carries only the bounded operation report. Snapshot admission uses an
explicit gate/scope pair and leaves the default aggregate child scope unchanged.

Offline reconstruction checks direct-input, full-lock and baseline identities,
loads the complete supplied cohort and reads actual installed producer/licence
bytes. The baseline selects source artifacts and authored declarations.
Publication creates a new candidate without replacing the baseline; read-only
comparison does not adopt it. Snapshot hashes bind the supplied bytes, not an
assurance of historical origin, administrator isolation or numerical validity.

The ordinary dependency consumer remains offline. The full aggregate can run
explicit owning tests that use external services; no network-free guarantee
applies to that complete test execution.
