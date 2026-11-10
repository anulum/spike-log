# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — canonical event column contracts

"""Check full native array order, value conservation and format refusals."""

from typing import NamedTuple

import pytest

from spike_log import DvsEvent, DvsGeometry, decode_dvs_columns, encode_dvs_columns
from spike_log.dvs_columns import PolarityConvention

GEOMETRY = DvsGeometry(4, 3)
EVENTS = (DvsEvent(-1, 1, 2, -1, 7), DvsEvent(0, 3, 1, 1, 7))
COLUMN_BYTES = bytes.fromhex("ffffffffffffffff00000000000000000100030002000100ff0107000700")


def test_five_consecutive_arrays_have_exact_independent_bytes() -> None:
    """Compare the full public encoder output with the literal native layout."""
    actual = encode_dvs_columns(
        EVENTS,
        geometry=GEOMETRY,
        stream_id=7,
        polarity="minus_plus",
        declared_order="per_stream_nondecreasing",
        max_events=2,
        max_payload_bytes=30,
    )
    assert actual == COLUMN_BYTES
    assert (
        decode_dvs_columns(
            COLUMN_BYTES,
            event_count=2,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=2,
            max_payload_bytes=30,
        )
        == EVENTS
    )


def test_nondecreasing_ties_and_duplicate_occurrences_are_preserved() -> None:
    """Keep all original records without sorting or deduplication."""
    event = DvsEvent(-2, 1, 1, 0, 0)
    records = (event, event, DvsEvent(9, 0, 0, 1, 0))
    data = encode_dvs_columns(
        records,
        geometry=GEOMETRY,
        stream_id=0,
        polarity="zero_one",
        declared_order="per_stream_nondecreasing",
        max_events=3,
        max_payload_bytes=45,
    )
    assert (
        decode_dvs_columns(
            data,
            event_count=3,
            geometry=GEOMETRY,
            stream_id=0,
            polarity="zero_one",
            declared_order="per_stream_nondecreasing",
            max_events=3,
            max_payload_bytes=45,
        )
        == records
    )


def test_all_representable_coordinate_and_tick_endpoints() -> None:
    """Retain both signed64 endpoints and the highest unsigned16 addresses."""
    records = (
        DvsEvent(-(1 << 63), 0, 65535, 0, 65535),
        DvsEvent((1 << 63) - 1, 65535, 0, 1, 65535),
    )
    geometry = DvsGeometry(65536, 65536)
    data = encode_dvs_columns(
        records,
        geometry=geometry,
        stream_id=65535,
        polarity="zero_one",
        declared_order="per_stream_nondecreasing",
        max_events=1 << 80,
        max_payload_bytes=1 << 80,
    )
    assert (
        decode_dvs_columns(
            data,
            event_count=2,
            geometry=geometry,
            stream_id=65535,
            polarity="zero_one",
            declared_order="per_stream_nondecreasing",
            max_events=1 << 80,
            max_payload_bytes=1 << 80,
        )
        == records
    )


@pytest.mark.parametrize(
    "fields",
    [
        (-(1 << 63) - 1, 0, 0, 1, 0),
        (1 << 63, 0, 0, 1, 0),
        (True, 0, 0, 1, 0),
        (0.5, 0, 0, 1, 0),
        (0, -1, 0, 1, 0),
        (0, 65536, 0, 1, 0),
        (0, True, 0, 1, 0),
        (0, 0, -1, 1, 0),
        (0, 0, 65536, 1, 0),
        (0, 0, 0.5, 1, 0),
        (0, 0, 0, -129, 0),
        (0, 0, 0, 128, 0),
        (0, 0, 0, True, 0),
        (0, 0, 0, 1, -1),
        (0, 0, 0, 1, 65536),
        (0, 0, 0, 1, False),
    ],
)
def test_original_field_values_are_never_coerced(
    fields: tuple[int, int, int, int, int],
) -> None:
    """Refuse fractional, Boolean and overflowing originals before packing."""
    with pytest.raises(ValueError):
        DvsEvent(*fields)


@pytest.mark.parametrize(
    ("width", "height"),
    [(0, 1), (65537, 1), (True, 1), (1, 0), (1, 65537), (1, 1.5)],
)
def test_geometry_is_an_exact_addressable_extent(width: int, height: int) -> None:
    """Reject empty, fractional, Boolean or unaddressable dimensions."""
    with pytest.raises(ValueError):
        DvsGeometry(width, height)


@pytest.mark.parametrize(
    ("events", "stream", "polarity", "count_limit", "byte_limit"),
    [
        ((), 7, "minus_plus", 2, 30),
        (EVENTS, -1, "minus_plus", 2, 30),
        (EVENTS, 65536, "minus_plus", 2, 30),
        (EVENTS, 7, "minus_plus", 0, 30),
        (EVENTS, 7, "minus_plus", True, 30),
        (EVENTS, 7, "minus_plus", 2, 0),
        (EVENTS, 7, "minus_plus", 2, 0.5),
        (EVENTS, 7, "minus_plus", 1, 30),
        (EVENTS, 7, "minus_plus", 2, 29),
        (EVENTS, 7, "not_applicable", 2, 30),
        (EVENTS, 8, "minus_plus", 2, 30),
        (EVENTS, 7, "zero_one", 2, 30),
        ((DvsEvent(0, 4, 0, 1, 7),), 7, "minus_plus", 1, 15),
        ((DvsEvent(0, 0, 3, 1, 7),), 7, "minus_plus", 1, 15),
        ([DvsEvent(0, 0, 0, 1, 7)], 7, "minus_plus", 1, 15),
    ],
)
def test_encoder_refuses_wrong_context_and_resource_scope(
    events: tuple[DvsEvent, ...],
    stream: int,
    polarity: PolarityConvention,
    count_limit: int,
    byte_limit: int,
) -> None:
    """Exercise real public encoder refusals without changing the source records."""
    before = tuple(events)
    with pytest.raises(ValueError):
        encode_dvs_columns(
            events,
            geometry=GEOMETRY,
            stream_id=stream,
            polarity=polarity,
            declared_order="per_stream_nondecreasing",
            max_events=count_limit,
            max_payload_bytes=byte_limit,
        )
    assert tuple(events) == before


@pytest.mark.parametrize(
    ("payload", "count"),
    [
        (COLUMN_BYTES[:-1], 2),
        (COLUMN_BYTES + b"\0", 2),
        (bytearray(COLUMN_BYTES), 2),
        (b"", 0),
        (COLUMN_BYTES, -1),
        (COLUMN_BYTES, True),
        (COLUMN_BYTES, 1 << 64),
    ],
)
def test_decoder_requires_the_exact_timed_shape(payload: bytes, count: int) -> None:
    """Refuse truncation, padding, mutable bytes and invalid declared counts."""
    with pytest.raises(ValueError):
        decode_dvs_columns(
            payload,
            event_count=count,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=2,
            max_payload_bytes=30,
        )


@pytest.mark.parametrize(("offset", "replacement"), [(16, 4), (20, 3), (24, 0), (26, 8)])
def test_decoder_checks_each_original_context_field(
    offset: int,
    replacement: int,
) -> None:
    """Detect a wrong coordinate, polarity or stream in actual column bytes."""
    changed = bytearray(COLUMN_BYTES)
    changed[offset] = replacement
    with pytest.raises(ValueError):
        decode_dvs_columns(
            bytes(changed),
            event_count=2,
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=2,
            max_payload_bytes=30,
        )


class DvsLookalike(NamedTuple):
    """A real tuple with similar attributes is not a validated native event."""

    tick: int
    x: int
    y: int
    polarity: int
    stream_id: int


class DerivedDvsEvent(DvsEvent):
    """An event subclass is outside the exact immutable wire-input contract."""


class GeometryLookalike(NamedTuple):
    """An extent tuple does not establish the actual validated geometry."""

    width: int
    height: int


@pytest.mark.parametrize(
    "event",
    [
        DvsLookalike(True, 0, 0, 1, 7),
        DvsLookalike(1 << 70, 0, 0, 1, 7),
        DerivedDvsEvent(0, 0, 0, 1, 7),
        object(),
    ],
)
def test_encoder_rejects_nonexact_event_types(event: DvsEvent) -> None:
    """Refuse Boolean/overflow lookalikes, subclasses and missing attributes."""
    with pytest.raises(ValueError):
        encode_dvs_columns(
            (event,),
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=1,
            max_payload_bytes=15,
        )


@pytest.mark.parametrize("tick", [True, 1 << 70])
def test_changed_frozen_original_fields_are_revalidated(tick: int) -> None:
    """An exact instance cannot bypass original-value checks after alteration."""
    event = DvsEvent(0, 0, 0, 1, 7)
    object.__setattr__(event, "tick", tick)
    with pytest.raises(ValueError):
        encode_dvs_columns(
            (event,),
            geometry=GEOMETRY,
            stream_id=7,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=1,
            max_payload_bytes=15,
        )


@pytest.mark.parametrize("geometry", [GeometryLookalike(True, 3), object()])
def test_geometry_requires_the_exact_validated_context(geometry: DvsGeometry) -> None:
    """Reject duck-typed or missing geometry through both payload entry points."""
    with pytest.raises(ValueError):
        encode_dvs_columns(
            EVENTS,
            geometry=geometry,
            stream_id=7,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=2,
            max_payload_bytes=30,
        )
    with pytest.raises(ValueError):
        decode_dvs_columns(
            COLUMN_BYTES,
            event_count=2,
            geometry=geometry,
            stream_id=7,
            polarity="minus_plus",
            declared_order="per_stream_nondecreasing",
            max_events=2,
            max_payload_bytes=30,
        )
