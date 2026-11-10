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

The planned `.slog` container preserves event-stream bytes, ordering, timebase and source provenance across recording, replay and derived slices. Domain runtime is not qualified during local scaffold construction.

The [native payload API](native-payloads.md) documents the implemented Python
codecs for canonical DVS columns and logical source records. Container, source,
clock and current-evidence qualification remain separate.

Start with [first local checks](validation-tooling.md#first-local-checks) to inspect the existing scaffold and read its diagnostic results. The commands qualify repository tooling; the event-stream runtime remains planned.

Read [architecture](ARCHITECTURE.md), [validation tooling](validation-tooling.md), [threat model](THREAT_MODEL.md) and [repository boundary](adr/0001-repository-boundary.md).


For dependency-source work, follow the [source workflow](validation-tooling.md#offline-source-workflow).
It separates explicit registry capture from offline reconstruction and
comparison. A passing candidate comparison does not adopt source bindings
or renew audit admission. Registry capture runs in a fixed installed worker
under one execution/cleanup budget, with an explicit capture-only duration
control.
