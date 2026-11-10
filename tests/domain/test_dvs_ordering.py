# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — declared event order and occurrence conservation

"""Exercise explicit order, repeated occurrences and real payload client partitions."""

import struct

import pytest

from spike_log import DvsEvent, DvsGeometry, decode_dvs_columns, encode_dvs_columns
from spike_log.dvs_columns import DeclaredOrder

GEOMETRY = DvsGeometry(4, 3)
EVENTS = (DvsEvent(-1, 1, 2, -1, 7), DvsEvent(0, 3, 1, 1, 7))
COLUMN_BYTES = bytes.fromhex("ffffffffffffffff00000000000000000100030002000100ff0107000700")


@pytest.mark.parametrize("mode", ["", "nondecreasing", None, False, 0])
def test_declared_order_is_explicit_and_exact(mode: DeclaredOrder) -> None:
    """Refuse unknown or nonstring declarations before interpreting records."""
    with pytest.raises(ValueError):
        encode_dvs_columns(
            EVENTS,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order=mode,
            max_events=2,
            max_payload_bytes=30,
        )
    with pytest.raises(ValueError):
        decode_dvs_columns(
            COLUMN_BYTES,
            event_count=2,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order=mode,
            max_events=2,
            max_payload_bytes=30,
        )


@pytest.mark.parametrize(
    ("ticks", "mode", "refuses"),
    [
        ((1, 0, 2), "per_stream_nondecreasing", True),
        ((1, 0, 1), "per_stream_nondecreasing", True),
        ((1, 0, 1), "explicit_unsorted", False),
        ((1, 1, 2), "explicit_unsorted", False),
        ((1, 1, 0), "explicit_unsorted", False),
    ],
)
def test_encoder_and_independent_decoder_enforce_order(
    ticks: tuple[int, int, int], mode: DeclaredOrder, refuses: bool
) -> None:
    """Keep original case inputs under the occurrence-preserving source law."""
    events = tuple(DvsEvent(tick, 0, 0, 1, 0) for tick in ticks)
    raw = struct.pack("<3q", *ticks) + bytes.fromhex("000000000000000000000000010101000000000000")
    if refuses:
        with pytest.raises(ValueError):
            encode_dvs_columns(
                events,
                geometry=GEOMETRY,
                stream_id=0,
                polarity="zero_one",
                declared_order=mode,
                max_events=3,
                max_payload_bytes=45,
            )
        with pytest.raises(ValueError):
            decode_dvs_columns(
                raw,
                event_count=3,
                geometry=GEOMETRY,
                stream_id=0,
                polarity="zero_one",
                declared_order=mode,
                max_events=3,
                max_payload_bytes=45,
            )
    else:
        assert (
            encode_dvs_columns(
                events,
                geometry=GEOMETRY,
                stream_id=0,
                polarity="zero_one",
                declared_order=mode,
                max_events=3,
                max_payload_bytes=45,
            )
            == raw
        )
        assert (
            decode_dvs_columns(
                raw,
                event_count=3,
                geometry=GEOMETRY,
                stream_id=0,
                polarity="zero_one",
                declared_order=mode,
                max_events=3,
                max_payload_bytes=45,
            )
            == events
        )


def test_distinct_unsorted_ticks_preserve_exact_original_order() -> None:
    """Retain negative unsorted source order against independent literal arrays."""
    raw = bytes.fromhex(
        "0900000000000000fefffffffffffffffcffffffffffffff000000000000000000000000010101000000000000"
    )
    events = (DvsEvent(9, 0, 0, 1, 0), DvsEvent(-2, 0, 0, 1, 0), DvsEvent(-4, 0, 0, 1, 0))
    assert (
        encode_dvs_columns(
            events,
            geometry=GEOMETRY,
            stream_id=0,
            polarity="zero_one",
            declared_order="explicit_unsorted",
            max_events=3,
            max_payload_bytes=45,
        )
        == raw
    )
    assert (
        decode_dvs_columns(
            raw,
            event_count=3,
            geometry=GEOMETRY,
            stream_id=0,
            polarity="zero_one",
            declared_order="explicit_unsorted",
            max_events=3,
            max_payload_bytes=45,
        )
        == events
    )


@pytest.mark.parametrize("batch_size", [1, 2, 3])
def test_unsorted_partitioning_preserves_every_original_occurrence(batch_size: int) -> None:
    """Changing payload boundaries cannot drop repeated or descending records."""
    repeated = DvsEvent(1, 0, 0, 1, 7)
    events = (repeated, DvsEvent(0, 0, 0, 1, 7), repeated)
    restored: list[DvsEvent] = []
    for start in range(0, len(events), batch_size):
        batch = events[start : start + batch_size]
        raw = encode_dvs_columns(
            batch,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="explicit_unsorted",
            max_events=batch_size,
            max_payload_bytes=15 * batch_size,
        )
        restored.extend(
            decode_dvs_columns(
                raw,
                event_count=len(batch),
                geometry=GEOMETRY,
                stream_id=7,
                polarity="minus_plus",
                declared_order="explicit_unsorted",
                max_events=batch_size,
                max_payload_bytes=15 * batch_size,
            )
        )
    assert tuple(restored) == events


def test_payload_clients_preserve_interleaved_stream_occurrences() -> None:
    """Retain A,B,A without imposing a false global timestamp ordering."""
    first = DvsEvent(1, 1, 0, 1, 7)
    events = (first, DvsEvent(0, 0, 1, 1, 8), first)
    restored: list[DvsEvent] = []
    for event in events:
        raw = encode_dvs_columns(
            (event,),
            geometry=GEOMETRY,
            stream_id=event.stream_id,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=1,
            max_payload_bytes=15,
        )
        restored.extend(
            decode_dvs_columns(
                raw,
                event_count=1,
                geometry=GEOMETRY,
                stream_id=event.stream_id,
                polarity="minus_plus",
                declared_order="per_stream_nondecreasing",
                max_events=1,
                max_payload_bytes=15,
            )
        )
    assert tuple(restored) == events


@pytest.mark.parametrize(
    ("offset", "field", "value"),
    [
        (24, "x", 4),
        (36, "polarity", 0),
        (39, "stream_id", 8),
    ],
)
def test_unsorted_ties_do_not_mask_invalid_original_context(
    offset: int, field: str, value: int
) -> None:
    """Permitting unsorted ties never hides geometry, polarity or stream faults."""
    original = dict(tick=1, x=0, y=0, polarity=1, stream_id=7)
    original[field] = value
    events = (DvsEvent(**original), DvsEvent(0, 0, 0, 1, 7), DvsEvent(1, 0, 0, 1, 7))
    raw = bytearray(struct.pack("<3q", 1, 0, 1) + bytes(12) + bytes([1, 1, 1]) + bytes([7, 0]) * 3)
    raw[offset] = value
    with pytest.raises(ValueError):
        encode_dvs_columns(
            events,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="explicit_unsorted",
            max_events=3,
            max_payload_bytes=45,
        )
    with pytest.raises(ValueError):
        decode_dvs_columns(
            bytes(raw),
            event_count=3,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="explicit_unsorted",
            max_events=3,
            max_payload_bytes=45,
        )
