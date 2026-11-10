# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — logical source record bytes

"""Retain source-scoped logical output identities in the selected timed codec."""

import struct
from dataclasses import dataclass


def _integer(value: int, low: int, high: int, field: str) -> None:
    """Reject coercion and values outside the exact native integer width."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field} must be an integer in [{low}, {high}]")


@dataclass(frozen=True, slots=True)
class LogicalEvent:
    """Retain one ordered logical source occurrence.

    Attributes
    ----------
    tick : int
        Original signed64 native tick after the explicitly selected time mapping.
    unit_id : int
        Unsigned64 identity in the full earlier source population. The plan
        distinguishes a neuron from a non-neural binary output channel.
    """

    tick: int
    unit_id: int

    def __post_init__(self) -> None:
        """Validate original values before any binary representation."""
        _integer(self.tick, -(1 << 63), (1 << 63) - 1, "tick")
        _integer(self.unit_id, 0, (1 << 64) - 1, "unit_id")


def _context(
    count: int,
    unit_ids: tuple[int, ...],
    max_events: int,
    max_payload_bytes: int,
    max_units: int,
) -> frozenset[int]:
    """Validate bounded timed population and the full distinct source inventory."""
    _integer(count, 1, (1 << 64) - 1, "event_count")
    for name, value in (
        ("max_events", max_events),
        ("max_payload_bytes", max_payload_bytes),
        ("max_units", max_units),
    ):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be an exact positive integer")
    if count > max_events or 16 * count > max_payload_bytes:
        raise ValueError("logical timed payload exceeds the selected bounds")
    if type(unit_ids) is not tuple:
        raise ValueError("an immutable complete source inventory is required")
    if not unit_ids or len(unit_ids) > max_units:
        raise ValueError("complete logical source inventory exceeds its bound")
    for value in unit_ids:
        _integer(value, 0, (1 << 64) - 1, "unit_id")
    selected = frozenset(unit_ids)
    if len(selected) != len(unit_ids):
        raise ValueError("complete logical source inventory has duplicate identities")
    return selected


def encode_logical_records(
    events: tuple[LogicalEvent, ...],
    *,
    unit_ids: tuple[int, ...],
    max_events: int,
    max_payload_bytes: int,
    max_units: int,
) -> bytes:
    """Encode the complete ordered timed branch of the logical spike codec.

    Parameters
    ----------
    events : tuple of LogicalEvent
        Nonempty immutable tuple of exact LogicalEvent objects, including
        duplicates and ties. Source values are revalidated before packing.
    unit_ids : tuple of int
        Complete unique source inventory, including silent units.
    max_events, max_payload_bytes, max_units : int
        Explicit positive event, decoded-byte and distinct inventory quotas.
        The caller separately admits source and output-buffer memory.

    Returns
    -------
    bytes
        Consecutive signed64-tick/unsigned64-unit records, little-endian,
        exactly 16 bytes per occurrence.

    Raises
    ------
    ValueError
        Invalid context, unknown unit, duplicate inventory identity, empty
        timed population or exceeded quota. The known metadata carrier is
        a separate count-zero branch, never an empty timed byte string.
    """
    if type(events) is not tuple:
        raise ValueError("an immutable original logical event tuple is required")
    count = len(events)
    selected = _context(count, unit_ids, max_events, max_payload_bytes, max_units)
    for event in events:
        if type(event) is not LogicalEvent:
            raise ValueError("every logical event must be exactly LogicalEvent")
        event.__post_init__()
        if event.unit_id not in selected:
            raise ValueError("logical event unit lacks its earlier source identity")
    result = bytearray(16 * count)
    for index, event in enumerate(events):
        struct.pack_into("<qQ", result, 16 * index, event.tick, event.unit_id)
    return bytes(result)


def decode_logical_records(
    payload: bytes,
    *,
    event_count: int,
    unit_ids: tuple[int, ...],
    max_events: int,
    max_payload_bytes: int,
    max_units: int,
) -> tuple[LogicalEvent, ...]:
    """Interpret every timed record under the selected complete source inventory.

    Parameters
    ----------
    payload : bytes
        Immutable decoded source-side bytes, without outer framing.
    event_count : int
        Exact independently supplied positive timed count.
    unit_ids : tuple of int
        Complete earlier unique source inventory, including silent units.
    max_events, max_payload_bytes, max_units : int
        Explicit positive event, byte and inventory quotas, checked before
        allocation.

    Returns
    -------
    tuple of LogicalEvent
        All original timed occurrences in exact source order. No geometry,
        physical clock, source completeness or scientific admission is inferred.

    Raises
    ------
    ValueError
        Wrong payload kind/length, unknown unit, invalid inventory/count or
        resource bound. This function does not interpret metadata carriers.
    """
    selected = _context(event_count, unit_ids, max_events, max_payload_bytes, max_units)
    if type(payload) is not bytes or len(payload) != 16 * event_count:
        raise ValueError("logical timed payload has the wrong exact byte length")
    events: list[LogicalEvent] = []
    for tick, unit_id in struct.iter_unpack("<qQ", payload):
        if unit_id not in selected:
            raise ValueError("logical event unit lacks its earlier source identity")
        events.append(LogicalEvent(tick, unit_id))
    return tuple(events)
