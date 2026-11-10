# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — native container digest preimages

"""Calculate the exact container integrity components without accepting a source."""

import hashlib
import json
import re
import struct
from collections.abc import Iterable
from typing import Literal

from evidence_manifest_toolkit import Limits, canonicalize_json

type Encoding = Literal["canonical_event_columns_le_v1", "source_side_stream_bytes"]


def _integer(value: int, low: int, high: int, field: str) -> None:
    """Require an exact native integer before constructing its wire representation."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError(field + " is outside its exact native integer range")


def _positive(value: int, field: str) -> None:
    """Refuse Boolean, fractional and nonpositive caller resource ceilings."""
    if type(value) is not int or value <= 0:
        raise ValueError(field + " must be an exact positive integer")


def _payload(payload: bytes, maximum: int) -> None:
    """Bound complete immutable nonempty decoded bytes before hashing."""
    _positive(maximum, "max_payload_bytes")
    if type(payload) is not bytes or not 0 < len(payload) <= maximum:
        raise ValueError("decoded payload violates its byte bound")


def _safe_json_integer(token: str) -> int:
    """Refuse an unsafe original integer token before its rounded bytes are hashed."""
    value = int(token)
    _integer(value, -((1 << 53) - 1), (1 << 53) - 1, "JSON integer")
    return value


def _canonical_object(data: bytes, limits: Limits) -> bytes:
    """Use the public Common parser and canonicalizer under both byte ceilings."""
    limits.validate()
    if type(data) is not bytes or len(data) > limits.max_blob_bytes:
        raise ValueError("JSON input violates its blob byte bound")
    canonical = canonicalize_json(data, limits=limits)
    json.loads(data, parse_int=_safe_json_integer)
    if not canonical.startswith(b"{"):
        raise ValueError("an original JSON object is required")
    if len(canonical) > min(limits.max_json_bytes, limits.max_blob_bytes):
        raise ValueError("canonical JSON violates its byte bound")
    return canonical


def _encoding(value: object) -> int:
    """Acquire the exact native discriminant from an independently selected value."""
    if type(value) is not str or value not in (
        "canonical_event_columns_le_v1",
        "source_side_stream_bytes",
    ):
        raise ValueError("the exact selected chunk encoding is required")
    return 0 if value == "canonical_event_columns_le_v1" else 1


def _digest_bytes(value: str) -> bytes:
    """Decode only a complete lower-case algorithm-qualified SHA-256 identity."""
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise ValueError("a complete lower-case SHA-256 identity is required")
    return bytes.fromhex(value[7:])


def header_digest(header_json: bytes, *, limits: Limits) -> str:
    """Hash the exact domain prefix and Common-canonical header object.

    Parameters
    ----------
    header_json : bytes
        Complete bounded strict JSON object, retained without mutation.
    limits : Limits
        Explicit Common document, blob and parser bounds.

    Returns
    -------
    str
        Algorithm-qualified initial chain identity. No schema, source, clock
        or claim acceptance is established by this calculation.

    Raises
    ------
    ValueError
        The input is not a bounded immutable JSON object.
    evidence_manifest_toolkit.EmtError
        Common strict JSON, number, Unicode or resource admission fails.
    """
    canonical = _canonical_object(header_json, limits)
    return "sha256:" + hashlib.sha256(b"slog.header.v1\x00" + canonical).hexdigest()


def timed_chunk_digest(
    sequence: int,
    stream_id: int,
    event_count: int,
    first_tick: int,
    last_tick: int,
    encoding: Encoding,
    payload: bytes,
    *,
    max_payload_bytes: int,
) -> str:
    """Hash the unchanged timed chunk preimage over every decoded payload byte.

    Parameters
    ----------
    sequence, stream_id, event_count : int
        Exact unsigned64 sequence/count and unsigned16 stream identity; count
        is positive. Stream identity is encoded as unsigned64 in this preimage.
    first_tick, last_tick : int
        Independently validated actual signed64 minimum and maximum ticks.
    encoding : {"canonical_event_columns_le_v1", "source_side_stream_bytes"}
        Exact selected encoding; represented by byte zero or one respectively.
    payload : bytes
        Complete nonempty decoded source bytes. Canonical columns require
        exactly fifteen bytes per timed event.
    max_payload_bytes : int
        Positive inherited decoded-byte ceiling, checked before hashing.

    Returns
    -------
    str
        Algorithm-qualified timed integrity component, without source acceptance.

    Raises
    ------
    ValueError
        A scalar, range, encoding, payload length or resource limit refuses.
        Actual codec decoding and extrema checks remain caller responsibilities.
    """
    _integer(sequence, 0, (1 << 64) - 1, "sequence")
    _integer(stream_id, 0, (1 << 16) - 1, "stream_id")
    _integer(event_count, 1, (1 << 64) - 1, "event_count")
    _integer(first_tick, -(1 << 63), (1 << 63) - 1, "first_tick")
    _integer(last_tick, -(1 << 63), (1 << 63) - 1, "last_tick")
    if first_tick > last_tick:
        raise ValueError("timed extrema are reversed")
    encoding_byte = _encoding(encoding)
    _payload(payload, max_payload_bytes)
    if encoding == "canonical_event_columns_le_v1" and len(payload) != 15 * event_count:
        raise ValueError("canonical columns have the wrong exact byte length")
    prefix = b"slog.chunk.v1\x00" + struct.pack(
        "<QQQqqBQ",
        sequence,
        stream_id,
        event_count,
        first_tick,
        last_tick,
        encoding_byte,
        len(payload),
    )
    digest = hashlib.sha256(prefix)
    digest.update(payload)
    return "sha256:" + digest.hexdigest()


def metadata_chunk_digest(
    sequence: int, stream_id: int, payload: bytes, *, max_payload_bytes: int
) -> str:
    """Hash the separate zero-timed auxiliary metadata preimage without tick fields.

    Parameters
    ----------
    sequence, stream_id : int
        Exact unsigned64 sequence and unsigned16 stream identity.
    payload : bytes
        Actual positive-length decoded carrier bytes. This calculation does not
        determine whether the independently selected source codec admits them.
    max_payload_bytes : int
        Positive inherited decoded-byte ceiling.

    Returns
    -------
    str
        Metadata-domain identity binding count zero, encoding one and the full
        actual byte length. Null bounds are never encoded as numeric zero.

    Raises
    ------
    ValueError
        Native widths, immutable nonempty bytes or resource admission fails.
    """
    _integer(sequence, 0, (1 << 64) - 1, "sequence")
    _integer(stream_id, 0, (1 << 16) - 1, "stream_id")
    _payload(payload, max_payload_bytes)
    prefix = b"slog.metadata.chunk.v1\x00" + struct.pack(
        "<QQQBQ",
        sequence,
        stream_id,
        0,
        1,
        len(payload),
    )
    digest = hashlib.sha256(prefix)
    digest.update(payload)
    return "sha256:" + digest.hexdigest()


def fold_chain(previous_digest: str, chunk_digest: str) -> str:
    """Fold the previous chain and next chunk identities in their exact order.

    Parameters
    ----------
    previous_digest, chunk_digest : str
        Complete lower-case algorithm-qualified SHA-256 values. The first
        previous identity is the actual header digest, never an implicit zero.

    Returns
    -------
    str
        Domain-separated next chain identity; no signature or seal is implied.

    Raises
    ------
    ValueError
        Either whole digest declaration is malformed.
    """
    previous = _digest_bytes(previous_digest)
    chunk = _digest_bytes(chunk_digest)
    return "sha256:" + hashlib.sha256(b"slog.chain.v1\x00" + previous + chunk).hexdigest()


def index_digest(
    rows: Iterable[bytes], *, max_rows: int, max_index_bytes: int, limits: Limits
) -> str:
    """Hash the canonical index array one bounded original row at a time.

    Parameters
    ----------
    rows : iterable of bytes
        Complete ordered strict JSON row objects. The caller independently
        validates row schema, original chunk offsets, lengths and identities.
        Rows are acquired only once and are never accumulated in memory.
    max_rows : int
        Positive inherited row-count ceiling; a genuinely empty index is valid.
    max_index_bytes : int
        Positive whole-operation ceiling applied separately to cumulative
        original and canonical row bytes, including array delimiters and commas.
    limits : Limits
        Explicit Common bounds for each row. Whole-index counters never reset
        when another row is canonicalized.

    Returns
    -------
    str
        Domain-separated SHA-256 of JCS(index), without index-schema or container
        acceptance. No index storage, network, file or source read is selected.

    Raises
    ------
    ValueError
        A row kind, count or cumulative byte ceiling refuses.
    evidence_manifest_toolkit.EmtError
        Common parsing, canonicalization or limit configuration refuses.
    """
    limits.validate()
    _positive(max_rows, "max_rows")
    _positive(max_index_bytes, "max_index_bytes")
    if max_index_bytes < 2:
        raise ValueError("index delimiters exceed the cumulative byte bound")
    digest = hashlib.sha256(b"slog.index.v1\x00[")
    original_bytes = canonical_bytes = 2
    count = 0
    for row in rows:
        if count >= max_rows:
            raise ValueError("index row count exceeds its bound")
        if type(row) is not bytes:
            raise ValueError("an immutable original index row is required")
        separator = b"," if count else b""
        original_bytes += len(separator) + len(row)
        if original_bytes > max_index_bytes:
            raise ValueError("original index bytes exceed the cumulative bound")
        canonical = _canonical_object(row, limits)
        canonical_bytes += len(separator) + len(canonical)
        if canonical_bytes > max_index_bytes:
            raise ValueError("canonical index bytes exceed the cumulative bound")
        digest.update(separator)
        digest.update(canonical)
        count += 1
    digest.update(b"]")
    return "sha256:" + digest.hexdigest()
