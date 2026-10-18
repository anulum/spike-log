<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->
# Repository boundary

Status: accepted product boundary; event-stream runtime remains planned.
Repository validation and dependency-source tooling are separate scaffold
implementation with their own acceptance.

SPIKE-LOG owns the `.slog` recording/replay container and record, replay, inspect, verify and slice surfaces. External format conversion remains with SPIKE-FORMAT-BRIDGE; quality and stimulus generation remain separate. Hardware instrumentation stays with LOOP-TIMING-WITNESS, and neural source/adapters stay with SC-NeuroCore.

Capture uses an existing immutable plan; output containers and final results follow in acyclic order. Slices and partial recovery are new identities. Requested replay timing is not a physical guarantee. Shared evidence primitives are consumed through their genuine installed APIs instead of copied into the container product.


Local tooling keeps four metadata-writing operations explicit: inventory,
audit admission, registry-source snapshot and prospective provenance.
Their outputs have separate owners and purposes. Offline verification does
not invoke a writer as a repair; comparison does not adopt a candidate.
Registry-source capture uses the existing bounded runner with a fixed installed
worker. Input validation, acquisition, publication and readback share its
inclusive execution/cleanup budget. The explicit snapshot scope does not change
the default local-scaffold child admission contract.
The eighteen-role aggregate and its maintained source populations remain
separate from these standalone operation modes. See the
[implemented data flow](../ARCHITECTURE.md#commands-data-and-publication-ownership).
