<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->
# SPIKE-LOG

SPIKE-LOG is the planned record and replay container for event streams. The selected design stores ordered canonical events and source-native side streams in chunked `.slog` files, with an index, integrity chain, capture provenance and a detached evidence seal.

The repository is under local scaffold construction. Evidence maturity is `architecture_only`; implemented domain capabilities, public claims and qualified schema inventories are empty. No container writer, capture adapter, replay engine or physical measurement is qualified here.

## Repository tooling

The local scaffold has metadata/inventory checks and explicit dependency
source capture, prospective provenance generation and offline comparison.
Start with [local checks](docs/validation-tooling.md#first-local-checks);
[source preparation](docs/validation-tooling.md#offline-source-workflow)
explains inputs and retained outputs. These tooling commands are separate
from the planned event-stream record/capture/replay runtime. Registry capture
uses a bounded installed worker; its budget control and retained snapshot
behaviour are documented in the source workflow.

## Boundary

The product owns recording, replay, metadata inspection, complete container verification and provenance-preserving slicing. External format conversion belongs to SPIKE-FORMAT-BRIDGE. Event quality judgement and ground-truth generation belong to their own tools. LOOP-TIMING-WITNESS owns capture instrumentation; SC-NeuroCore owns neural adapters and model outputs.

Logical replay preserves original values, ticks and ordering. Requested native or scaled delivery does not guarantee wall-clock timing. A source-native side stream retains its exact codec identity; archiving bytes does not qualify unknown neural semantics.

See [architecture](ARCHITECTURE.md), [roadmap](ROADMAP.md), [validation](VALIDATION.md) and [security](SECURITY.md). Contribution and support routes are [CONTRIBUTING.md](CONTRIBUTING.md) and [SUPPORT.md](SUPPORT.md).

## Licence and citation

AGPL-3.0-or-later; a commercial licence is available through [Anulum](https://www.anulum.li). See [NOTICE.md](NOTICE.md), [LICENSE](LICENSE) and [CITATION.cff](CITATION.cff). No release, package, DOI or hosted service is asserted by this local source tree.
