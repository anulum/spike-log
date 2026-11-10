<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — native payload API and typing
-->
# Native payload API

The Python package `spike_log` encodes and reads two distinct timed payload
formats. These functions retain complete original values and occurrence order.
They operate on decoded payload bytes; they do not create a container, interpret
a metadata-only carrier, infer a physical clock or accept a source's claims.

## Canonical DVS columns

A chunk contains five consecutive arrays: signed64 ticks, unsigned16 x,
unsigned16 y, signed8 polarity and unsigned16 stream IDs, all little-endian.
The exact length is `15 * event_count`. Every event has the same declared
chunk stream; coordinates must lie within the earlier image extent and
polarity follows the explicitly selected `minus_plus` or `zero_one` convention.

`DvsGeometry` stores pixel counts, not maximum coordinates. An extent of
65536 addresses values from0 through65535. Booleans, fractional values and
overflowing integers are rejected before packing. Encoding requires an immutable
tuple of exact DvsEvent instances. Pass the exact header declared_order:
per_stream_nondecreasing rejects descents within a stream; explicit_unsorted
makes no monotonicity or uniqueness claim. Both preserve equal timestamps,
duplicate records and the exact original occurrence order. Changing admitted
payload boundaries cannot alter that logical population.
The functions validate ordering within this payload. Whole-container acceptance
must additionally check per-stream order across chunk boundaries. Nothing is
sorted, deduplicated or narrowed; original fields and geometry are revalidated.

```python
from spike_log import DvsEvent, DvsGeometry, decode_dvs_columns, encode_dvs_columns

events = (DvsEvent(-1, 1, 2, -1, 7), DvsEvent(0, 3, 1, 1, 7))
geometry = DvsGeometry(width=4, height=3)
payload = encode_dvs_columns(
    events,
    geometry=geometry,
    stream_id=7,
    polarity="minus_plus",
    declared_order="per_stream_nondecreasing",
    max_events=2,
    max_payload_bytes=30,
)
assert decode_dvs_columns(
    payload,
    event_count=2,
    geometry=geometry,
    stream_id=7,
    polarity="minus_plus",
    declared_order="per_stream_nondecreasing",
    max_events=2,
    max_payload_bytes=30,
) == events
```

The count and byte values above describe those two events. Production callers
supply their admitted source/batch quotas and separately account for source,
decoded-record and output-buffer memory. Quotas are not limited to native
integer widths; actual wire fields retain their format bounds.

::: spike_log.dvs_columns

## Logical source records

A timed record contains one signed64 tick followed by one unsigned64
source-scoped logical-unit ID, little-endian, exactly16bytes. The earlier plan
distinguishes neurons from binary output channels. Unit IDs are never DVS pixel
coordinates, and matching integers from different populations do not establish
a shared identity.

Encoding requires exact LogicalEvent instances and revalidates original fields.
Pass the full immutable inventory, including silent units, with its own
`max_units` bound. The codec rejects unknown/duplicate identities and retains
every repeated occurrence. Empty timed payloads are refused: a genuinely empty
container and a known zero-count metadata carrier belong to their respective
container contracts.

```python
from spike_log import LogicalEvent, decode_logical_records, encode_logical_records

events = (LogicalEvent(0, 3), LogicalEvent(1, 0), LogicalEvent(1, 1))
inventory = (0, 1, 2, 3)
payload = encode_logical_records(
    events,
    unit_ids=inventory,
    max_events=3,
    max_payload_bytes=48,
    max_units=4,
)
assert decode_logical_records(
    payload,
    event_count=3,
    unit_ids=inventory,
    max_events=3,
    max_payload_bytes=48,
    max_units=4,
) == events
```

::: spike_log.logical_records


## Container integrity components

The package also exposes the container's five digest calculations.
They use the actual public Common canonicalizer for header and index JSON.
They calculate byte integrity only; they do not accept a schema, source codec,
capture plan, reference closure, physical clock or scientific claim.

| Public operation | Exact input and output |
| --- | --- |
| `header_digest` | Bounded strict header object, canonicalized under explicit Common Limits; returns the initial chain digest. |
| `timed_chunk_digest` | Exact native sequence, stream, positive count, signed bounds, selected encoding and all decoded bytes; returns the unchanged timed-domain digest. |
| `metadata_chunk_digest` | Exact sequence, stream and nonempty source-side bytes; hashes count zero with no tick slots under the separate metadata prefix. |
| `fold_chain` | Complete lower-case previous-chain and chunk digests, decoded to their original32byte values in that order. |
| `index_digest` | A single pass over ordered bounded row objects; hashes the canonical array without accumulating the complete index. |

All identities include the `sha256:` prefix. Native integer fields reject
Boolean, fractional and overflowing values before little-endian encoding.
Original numeric integer tokens outside the exact safe JSON interval
[-9007199254740991,9007199254740991] refuse before canonical bytes are hashed.
Native wide counts and ticks still use their schema-defined decimal strings.
Canonical DVS columns require exactly15bytes per event. A metadata payload's
actual positive length is hashed; null bounds are never replaced with0.
Changing bytes, order, sequence or the selected domain changes the identity.

Header and index operations require explicit Common `Limits`. Index callers
also supply positive `max_rows` and `max_index_bytes`. The latter bounds both
the cumulative original input and canonical index bytes, including commas and
array delimiters. Counters never reset between rows. Common's per-row JSON,
blob and depth bounds remain in force. Native source, buffer and index-storage
budgets are separate caller responsibilities.

The digest operations do not decode auxiliary bytes, recompute event extrema,
validate index offsets or construct a complete container. Those checks remain
with the source codec and complete reader/writer. An empty index can be hashed,
but a metadata-only chunk cannot be silently treated as an empty recording.
A matching component hash supplies neither a signature nor complete verification.

::: spike_log.container_digests
