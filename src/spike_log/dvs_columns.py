# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — canonical DVS event columns

"""Read and write the five consecutive little-endian canonical event arrays."""

import struct
from dataclasses import dataclass
from itertools import pairwise
from typing import Literal

PolarityConvention = Literal["minus_plus", "zero_one"]
DeclaredOrder = Literal["per_stream_nondecreasing", "explicit_unsorted"]


def _integer(value: int, low: int, high: int, field: str) -> None:
    """Reject coercion and values outside the original field's wire width."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field} must be an integer in [{low}, {high}]")


@dataclass(frozen=True, slots=True)
class DvsGeometry:
    """Declare the full addressable image extent.

    Attributes
    ----------
    width, height : int
        Pixel counts from one to 65536, addressing unsigned16 coordinates.
        These are extents, not maximum coordinate values.
    """

    width: int
    height: int

    def __post_init__(self) -> None:
        """Validate both extents before reading any event."""
        _integer(self.width, 1, 1 << 16, "width")
        _integer(self.height, 1, 1 << 16, "height")


@dataclass(frozen=True, slots=True)
class DvsEvent:
    """Retain one original canonical event without narrowing or normalisation.

    Attributes
    ----------
    tick : int
        Original signed64 source tick.
    x, y : int
        Original unsigned16 pixel coordinates.
    polarity : int
        Original signed8 value; the selected convention is checked by the codec.
    stream_id : int
        Original unsigned16 source-stream identity.
    """

    tick: int
    x: int
    y: int
    polarity: int
    stream_id: int

    def __post_init__(self) -> None:
        """Reject non-integer and overflowing original values."""
        _integer(self.tick, -(1 << 63), (1 << 63) - 1, "tick")
        _integer(self.x, 0, (1 << 16) - 1, "x")
        _integer(self.y, 0, (1 << 16) - 1, "y")
        _integer(self.polarity, -(1 << 7), (1 << 7) - 1, "polarity")
        _integer(self.stream_id, 0, (1 << 16) - 1, "stream_id")


def _context(
    count: int,
    geometry: DvsGeometry,
    stream_id: int,
    polarity: PolarityConvention,
    declared_order: object,
    max_events: int,
    max_payload_bytes: int,
) -> tuple[int, ...]:
    """Validate the complete timed payload bounds and selected convention."""
    _integer(count, 1, (1 << 64) - 1, "event_count")
    if type(geometry) is not DvsGeometry:
        raise ValueError("the exact earlier DVS geometry is required")
    geometry.__post_init__()
    if type(declared_order) is not str or declared_order not in (
        "per_stream_nondecreasing",
        "explicit_unsorted",
    ):
        raise ValueError("unknown declared event ordering")
    _integer(stream_id, 0, (1 << 16) - 1, "stream_id")
    for name, value in (("max_events", max_events), ("max_payload_bytes", max_payload_bytes)):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be an exact positive integer")
    if count > max_events or 15 * count > max_payload_bytes:
        raise ValueError("canonical event payload exceeds the selected bounds")
    if polarity == "minus_plus":
        return (-1, 1)
    if polarity == "zero_one":
        return (0, 1)
    raise ValueError("unknown DVS polarity convention")


def _event(
    event: DvsEvent,
    geometry: DvsGeometry,
    stream_id: int,
    allowed: tuple[int, ...],
) -> None:
    """Check source geometry, polarity and single-chunk stream identity."""
    if type(event) is not DvsEvent:
        raise ValueError("every canonical event must be exactly DvsEvent")
    event.__post_init__()
    if event.x >= geometry.width or event.y >= geometry.height:
        raise ValueError("event coordinate is outside the declared geometry")
    if event.stream_id != stream_id:
        raise ValueError("event stream differs from the selected chunk stream")
    if event.polarity not in allowed:
        raise ValueError("event polarity differs from the selected convention")


def _ordering(events: tuple[DvsEvent, ...], declared_order: DeclaredOrder) -> None:
    """Validate this payload's declared order without sorting or pruning."""
    if declared_order == "per_stream_nondecreasing":
        if any(current.tick < previous.tick for previous, current in pairwise(events)):
            raise ValueError("event ticks violate declared nondecreasing order")


def encode_dvs_columns(
    events: tuple[DvsEvent, ...],
    *,
    geometry: DvsGeometry,
    stream_id: int,
    polarity: PolarityConvention,
    declared_order: DeclaredOrder,
    max_events: int,
    max_payload_bytes: int,
) -> bytes:
    """Encode a nonempty timed chunk as five complete consecutive arrays.

    Parameters
    ----------
    events : tuple of DvsEvent
        Immutable tuple of exact DvsEvent objects. Both order declarations
        retain every tie and duplicate occurrence; no values are coerced.
    geometry : DvsGeometry
        Complete earlier image extent.
    stream_id : int
        Exact unsigned16 stream shared by every event in this chunk.
    polarity : {"minus_plus", "zero_one"}
        Earlier selected source convention.
    declared_order : {"per_stream_nondecreasing", "explicit_unsorted"}
        Exact earlier header declaration. Nondecreasing forbids descents;
        unsorted imposes no monotonicity or uniqueness rule. Both retain ties.
        Only this payload is checked: whole-container acceptance additionally
        requires per-stream checks across chunk boundaries.
    max_events, max_payload_bytes : int
        Explicit positive count and decoded-byte quotas. The caller admits
        memory for the source sequence, bounded ordering state and output buffers
        separately.

    Returns
    -------
    bytes
        Exactly 15 bytes per event: all ticks, x, y, polarity and stream IDs,
        without magic, padding, compression or reordering.

    Raises
    ------
    ValueError
        Empty timed population, invalid context, inconsistent source fields
        or an exceeded bound. Empty recordings have no canonical-event chunk.
    """
    if type(events) is not tuple:
        raise ValueError("an immutable original event tuple is required")
    count = len(events)
    allowed = _context(
        count, geometry, stream_id, polarity, declared_order, max_events, max_payload_bytes
    )
    for event in events:
        _event(event, geometry, stream_id, allowed)
    _ordering(events, declared_order)
    result = bytearray(15 * count)
    for index, event in enumerate(events):
        struct.pack_into("<q", result, 8 * index, event.tick)
        struct.pack_into("<H", result, 8 * count + 2 * index, event.x)
        struct.pack_into("<H", result, 10 * count + 2 * index, event.y)
        struct.pack_into("<b", result, 12 * count + index, event.polarity)
        struct.pack_into("<H", result, 13 * count + 2 * index, event.stream_id)
    return bytes(result)


def decode_dvs_columns(
    payload: bytes,
    *,
    event_count: int,
    geometry: DvsGeometry,
    stream_id: int,
    polarity: PolarityConvention,
    declared_order: DeclaredOrder,
    max_events: int,
    max_payload_bytes: int,
) -> tuple[DvsEvent, ...]:
    """Read every field of an exact canonical event payload.

    Parameters
    ----------
    payload : bytes
        Immutable decoded payload, without base64 or JSON framing.
    event_count : int
        Independently supplied positive native timed count.
    geometry : DvsGeometry
        Complete earlier image extent.
    stream_id : int
        Exact unsigned16 stream declared for this chunk.
    polarity : {"minus_plus", "zero_one"}
        Earlier selected source convention.
    declared_order : {"per_stream_nondecreasing", "explicit_unsorted"}
        Exact earlier header declaration. Nondecreasing forbids descents;
        unsorted imposes no monotonicity or uniqueness rule. Both retain ties.
        Only this payload is checked: whole-container acceptance additionally
        requires per-stream checks across chunk boundaries.
    max_events, max_payload_bytes : int
        Explicit count and decoded-byte quotas, checked before allocation.

    Returns
    -------
    tuple of DvsEvent
        Complete original array order, with no sorting, filtering or deduplication.

    Raises
    ------
    ValueError
        Wrong payload kind/length, context, count, geometry, polarity, stream
        or resource bound. This function does not accept metadata-only chunks.
    """
    allowed = _context(
        event_count, geometry, stream_id, polarity, declared_order, max_events, max_payload_bytes
    )
    if type(payload) is not bytes or len(payload) != 15 * event_count:
        raise ValueError("canonical event payload has the wrong exact byte length")
    events: list[DvsEvent] = []
    for index in range(event_count):
        event = DvsEvent(
            struct.unpack_from("<q", payload, 8 * index)[0],
            struct.unpack_from("<H", payload, 8 * event_count + 2 * index)[0],
            struct.unpack_from("<H", payload, 10 * event_count + 2 * index)[0],
            struct.unpack_from("<b", payload, 12 * event_count + index)[0],
            struct.unpack_from("<H", payload, 13 * event_count + 2 * index)[0],
        )
        _event(event, geometry, stream_id, allowed)
        events.append(event)
    result = tuple(events)
    _ordering(result, declared_order)
    return result
