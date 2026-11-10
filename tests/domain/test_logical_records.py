# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — logical output record contracts

"""Check the real logical source layout and full inventory/count boundaries."""

from typing import NamedTuple

import pytest

from spike_log import LogicalEvent, decode_logical_records, encode_logical_records

# First three original occurrences of the retained e4cc1583 feedforward capture.
SOURCE_PREFIX = bytes.fromhex(
    "00000000000000000300000000000000"
    "01000000000000000000000000000000"
    "01000000000000000100000000000000"
)
EVENTS = (LogicalEvent(0, 3), LogicalEvent(1, 0), LogicalEvent(1, 1))
INVENTORY = (0, 1, 2, 3)


def test_original_source_prefix_has_exact_full_record_bytes() -> None:
    """Read the genuine retained prefix, including its unused population unit."""
    assert (
        decode_logical_records(
            SOURCE_PREFIX,
            event_count=3,
            unit_ids=INVENTORY,
            max_events=3,
            max_payload_bytes=48,
            max_units=4,
        )
        == EVENTS
    )
    assert (
        encode_logical_records(
            EVENTS,
            unit_ids=INVENTORY,
            max_events=3,
            max_payload_bytes=48,
            max_units=4,
        )
        == SOURCE_PREFIX
    )


def test_signed_ticks_unsigned_units_and_duplicate_order() -> None:
    """Preserve extremes, negative/unsorted time and repeated occurrences."""
    high = (1 << 64) - 1
    event = LogicalEvent(-(1 << 63), 0)
    records = (LogicalEvent((1 << 63) - 1, high), event, event)
    raw = encode_logical_records(
        records,
        unit_ids=(high, 0, 7),
        max_events=1 << 80,
        max_payload_bytes=1 << 80,
        max_units=1 << 80,
    )
    assert raw[:16] == bytes.fromhex("ffffffffffffff7fffffffffffffffff")
    assert raw[16:32] == bytes.fromhex("00000000000000800000000000000000")
    assert raw[32:] == raw[16:32]
    assert (
        decode_logical_records(
            raw,
            event_count=3,
            unit_ids=(high, 0, 7),
            max_events=1 << 80,
            max_payload_bytes=1 << 80,
            max_units=1 << 80,
        )
        == records
    )


@pytest.mark.parametrize(
    ("tick", "unit"),
    [
        (-(1 << 63) - 1, 0),
        (1 << 63, 0),
        (True, 0),
        (0.5, 0),
        (0, -1),
        (0, 1 << 64),
        (0, False),
        (0, 0.5),
    ],
)
def test_original_record_fields_are_not_narrowed(tick: int, unit: int) -> None:
    """Reject bad original integers before they can acquire valid wire bits."""
    with pytest.raises(ValueError):
        LogicalEvent(tick, unit)


@pytest.mark.parametrize(
    ("events", "units", "count_limit", "byte_limit", "unit_limit"),
    [
        ((), INVENTORY, 3, 48, 4),
        (EVENTS, INVENTORY, 0, 48, 4),
        (EVENTS, INVENTORY, True, 48, 4),
        (EVENTS, INVENTORY, 3, 0, 4),
        (EVENTS, INVENTORY, 3, 0.5, 4),
        (EVENTS, INVENTORY, 3, 48, 0),
        (EVENTS, INVENTORY, 3, 48, True),
        (EVENTS, INVENTORY, 2, 48, 4),
        (EVENTS, INVENTORY, 3, 47, 4),
        (EVENTS, INVENTORY, 3, 48, 3),
        (EVENTS, (), 3, 48, 4),
        (EVENTS, (0, 1, 1, 3), 3, 48, 4),
        (EVENTS, (0, 1, 2, True), 3, 48, 4),
        (EVENTS, (0, 1, 2, 1 << 64), 3, 48, 4),
        (EVENTS, (0, 1, 2), 3, 48, 4),
        (EVENTS, [0, 1, 2, 3], 3, 48, 4),
        ([LogicalEvent(0, 3)], INVENTORY, 1, 16, 4),
    ],
)
def test_encoder_preserves_the_full_population_and_boundaries(
    events: tuple[LogicalEvent, ...],
    units: tuple[int, ...],
    count_limit: int,
    byte_limit: int,
    unit_limit: int,
) -> None:
    """Do not prune silent units, repair identities or reinterpret empty data."""
    before = tuple(events)
    with pytest.raises(ValueError):
        encode_logical_records(
            events,
            unit_ids=units,
            max_events=count_limit,
            max_payload_bytes=byte_limit,
            max_units=unit_limit,
        )
    assert tuple(events) == before


@pytest.mark.parametrize(
    ("payload", "count", "units"),
    [
        (SOURCE_PREFIX[:-1], 3, INVENTORY),
        (SOURCE_PREFIX + b"\0", 3, INVENTORY),
        (bytearray(SOURCE_PREFIX), 3, INVENTORY),
        (b"", 0, INVENTORY),
        (SOURCE_PREFIX, -1, INVENTORY),
        (SOURCE_PREFIX, True, INVENTORY),
        (SOURCE_PREFIX, 1 << 64, INVENTORY),
        (SOURCE_PREFIX, 3, (0, 1, 2)),
    ],
)
def test_decoder_rejects_missing_bytes_counts_or_source_identities(
    payload: bytes,
    count: int,
    units: tuple[int, ...],
) -> None:
    """Read the actual public decoder path for each incomplete source case."""
    with pytest.raises(ValueError):
        decode_logical_records(
            payload,
            event_count=count,
            unit_ids=units,
            max_events=3,
            max_payload_bytes=48,
            max_units=4,
        )


class LogicalLookalike(NamedTuple):
    """A similar tuple is not an exact source-validated logical event."""

    tick: int
    unit_id: int


class DerivedLogicalEvent(LogicalEvent):
    """An event subclass is outside the exact native input contract."""


@pytest.mark.parametrize(
    "event",
    [
        LogicalLookalike(True, 0),
        LogicalLookalike(1 << 70, 0),
        DerivedLogicalEvent(0, 0),
        object(),
    ],
)
def test_encoder_rejects_nonexact_logical_types(event: LogicalEvent) -> None:
    """Reject Boolean/overflow lookalikes, subclasses and absent fields."""
    with pytest.raises(ValueError):
        encode_logical_records(
            (event,),
            unit_ids=INVENTORY,
            max_events=1,
            max_payload_bytes=16,
            max_units=4,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tick", True),
        ("tick", 1 << 70),
        ("unit_id", False),
        ("unit_id", 1 << 70),
    ],
)
def test_changed_frozen_source_fields_cannot_acquire_valid_bits(field: str, value: int) -> None:
    """Revalidate exact instances before any original value is packed."""
    event = LogicalEvent(0, 0)
    object.__setattr__(event, field, value)
    with pytest.raises(ValueError):
        encode_logical_records(
            (event,),
            unit_ids=INVENTORY,
            max_events=1,
            max_payload_bytes=16,
            max_units=4,
        )
