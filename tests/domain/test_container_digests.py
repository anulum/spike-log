# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — independent container digest preimages

"""Compare public native digest APIs with literal framing and an independent SHA engine."""

import json
from collections.abc import Iterator

import pytest
from Crypto.Hash import SHA256
from evidence_manifest_toolkit import ConfigurationError, InputRefused, Limits

from spike_log import (
    DvsEvent,
    DvsGeometry,
    encode_dvs_columns,
    fold_chain,
    header_digest,
    index_digest,
    metadata_chunk_digest,
    timed_chunk_digest,
)
from spike_log.container_digests import Encoding

LIMITS = Limits(16384, 16384, 65536, 64, 16, 32)
EVENTS = (DvsEvent(-3, 1, 2, -1, 7), DvsEvent(4, 3, 1, 1, 7))
PAYLOAD = bytes.fromhex("fdffffffffffffff04000000000000000100030002000100ff0107000700")
ROWS = (
    b'{"sequence":"0","byte_offset":"321","byte_length":"280","event_count":"0","first_tick":null,"last_tick":null}',
    b'{"sequence":"1","byte_offset":"602","byte_length":"320","event_count":"2","first_tick":"-3","last_tick":"4"}',
)


def independent_sha(data: bytes) -> str:
    """Use PyCryptodome's actual SHA engine rather than production hashlib."""
    return "sha256:" + SHA256.new(data).hexdigest()


def test_public_timed_digest_matches_independent_literal_original_columns() -> None:
    """Actual public encoding and digest retain the unchanged timed preimage."""
    encoded = encode_dvs_columns(
        EVENTS,
        geometry=DvsGeometry(4, 3),
        stream_id=7,
        polarity="minus_plus",
        declared_order="per_stream_nondecreasing",
        max_events=2,
        max_payload_bytes=30,
    )
    assert encoded == PAYLOAD
    literal = (
        b"slog.chunk.v1\x00"
        + (9).to_bytes(8, "little")
        + (7).to_bytes(8, "little")
        + (2).to_bytes(8, "little")
        + (-3).to_bytes(8, "little", signed=True)
        + (4).to_bytes(8, "little", signed=True)
        + b"\x00"
        + (30).to_bytes(8, "little")
        + PAYLOAD
    )
    assert timed_chunk_digest(
        9, 7, 2, -3, 4, "canonical_event_columns_le_v1", encoded, max_payload_bytes=30
    ) == independent_sha(literal)


def test_auxiliary_timed_and_metadata_preimages_are_distinct_and_length_bound() -> None:
    """Count-zero metadata has no tick slots and hashes every actual carrier byte."""
    payload = b'{"kind":"capture_window","timed_event_count":"0"}'
    metadata = (
        b"slog.metadata.chunk.v1\x00"
        + (0).to_bytes(8, "little")
        + (7).to_bytes(8, "little")
        + (0).to_bytes(8, "little")
        + b"\x01"
        + len(payload).to_bytes(8, "little")
        + payload
    )
    actual = metadata_chunk_digest(0, 7, payload, max_payload_bytes=len(payload))
    assert actual == independent_sha(metadata)
    timed = (
        b"slog.chunk.v1\x00"
        + (0).to_bytes(8, "little")
        + (7).to_bytes(8, "little")
        + (1).to_bytes(8, "little")
        + (0).to_bytes(8, "little", signed=True) * 2
        + b"\x01"
        + len(payload).to_bytes(8, "little")
        + payload
    )
    other = timed_chunk_digest(
        0, 7, 1, 0, 0, "source_side_stream_bytes", payload, max_payload_bytes=len(payload)
    )
    assert other == independent_sha(timed) and other != actual
    assert metadata_chunk_digest(0, 7, payload + b" ", max_payload_bytes=len(payload) + 1) != actual


def test_extreme_native_widths_are_encoded_without_narrowing() -> None:
    """The actual uint64 and signed64 endpoint framing agrees with independent bytes."""
    maximum = (1 << 64) - 1
    payload = b"\x00" * 16
    expected = (
        b"slog.chunk.v1\x00"
        + maximum.to_bytes(8, "little")
        + (65535).to_bytes(8, "little")
        + maximum.to_bytes(8, "little")
        + (-(1 << 63)).to_bytes(8, "little", signed=True)
        + ((1 << 63) - 1).to_bytes(8, "little", signed=True)
        + b"\x01"
        + len(payload).to_bytes(8, "little")
        + payload
    )
    assert timed_chunk_digest(
        maximum,
        65535,
        maximum,
        -(1 << 63),
        (1 << 63) - 1,
        "source_side_stream_bytes",
        payload,
        max_payload_bytes=16,
    ) == independent_sha(expected)


@pytest.mark.parametrize(
    ("sequence", "stream", "count", "first", "last"),
    [
        (-1, 7, 2, -3, 4),
        (1 << 64, 7, 2, -3, 4),
        (False, 7, 2, -3, 4),
        (0, -1, 2, -3, 4),
        (0, 65536, 2, -3, 4),
        (0, 7, 0, -3, 4),
        (0, 7, 1 << 64, -3, 4),
        (0, 7, True, -3, 4),
        (0, 7, 2, -(1 << 63) - 1, 4),
        (0, 7, 2, -3, 1 << 63),
        (0, 7, 2, 5, 4),
        (0, 7, 2, -3.5, 4),
    ],
)
def test_timed_wire_scalar_failures(
    sequence: int, stream: int, count: int, first: int, last: int
) -> None:
    """Native coercion, overflow, Boolean counts and reversed extrema refuse."""
    with pytest.raises(ValueError):
        timed_chunk_digest(
            sequence,
            stream,
            count,
            first,
            last,
            "canonical_event_columns_le_v1",
            PAYLOAD,
            max_payload_bytes=30,
        )


@pytest.mark.parametrize("encoding", ["unknown", "CANONICAL_EVENT_COLUMNS_LE_V1", None])
def test_unknown_encoding_refuses(encoding: Encoding) -> None:
    """Only the two exact independent encoding declarations select a wire byte."""
    with pytest.raises(ValueError):
        timed_chunk_digest(0, 7, 2, -3, 4, encoding, PAYLOAD, max_payload_bytes=30)


@pytest.mark.parametrize(
    ("payload", "maximum"),
    [
        (b"", 30),
        (PAYLOAD[:-1], 30),
        (PAYLOAD, 29),
        (PAYLOAD, 0),
        (PAYLOAD, True),
        (bytearray(PAYLOAD), 30),
    ],
)
def test_timed_payload_and_budget_failures(payload: bytes, maximum: int) -> None:
    """Exact bytes, column length and positive inclusive bounds remain mandatory."""
    with pytest.raises(ValueError):
        timed_chunk_digest(
            0,
            7,
            2,
            -3,
            4,
            "canonical_event_columns_le_v1",
            payload,
            max_payload_bytes=maximum,
        )


@pytest.mark.parametrize(
    ("sequence", "stream", "payload", "maximum"),
    [
        (-1, 7, b"x", 1),
        (0, 65536, b"x", 1),
        (0, 7, b"", 1),
        (0, 7, b"metadata", 7),
        (0, 7, b"metadata", False),
    ],
)
def test_metadata_wire_failures(sequence: int, stream: int, payload: bytes, maximum: int) -> None:
    """A null-bound native branch never becomes an empty or coerced timed payload."""
    with pytest.raises(ValueError):
        metadata_chunk_digest(sequence, stream, payload, max_payload_bytes=maximum)


def test_common_header_canonicalization_and_ordered_chain_fold() -> None:
    """Public Common canonical bytes and independently decoded digests select the chain."""
    original = b' { "streams":[], "format":"slog-json-columnar-v1", "geometry":null } '
    canonical = b'{"format":"slog-json-columnar-v1","geometry":null,"streams":[]}'
    header = header_digest(original, limits=LIMITS)
    assert header == independent_sha(b"slog.header.v1\x00" + canonical)
    chunk = timed_chunk_digest(
        0, 7, 2, -3, 4, "canonical_event_columns_le_v1", PAYLOAD, max_payload_bytes=30
    )
    expected = independent_sha(
        b"slog.chain.v1\x00" + bytes.fromhex(header[7:]) + bytes.fromhex(chunk[7:])
    )
    assert fold_chain(header, chunk) == expected
    assert fold_chain(chunk, header) != expected


@pytest.mark.parametrize(
    ("raw", "error"),
    [
        (b'{"x":1,"x":2}', InputRefused),
        (b'{"x":NaN}', InputRefused),
        (b'{"x":"\xff"}', InputRefused),
        (b'{"x":9007199254740993}', ValueError),
        (b'{"x":100000000000000000000}', ValueError),
    ],
)
def test_original_common_json_refusals_remain_visible(raw: bytes, error: type[Exception]) -> None:
    """Duplicate, nonfinite, invalid UTF-8 and unsafe integer inputs remain refused."""
    with pytest.raises(error):
        header_digest(raw, limits=LIMITS)


@pytest.mark.parametrize("raw", [b"[]", b"null", bytearray(b"{}")])
def test_header_requires_an_immutable_object(raw: bytes) -> None:
    """A canonical scalar/array or mutable buffer cannot become a header object."""
    with pytest.raises(ValueError):
        header_digest(raw, limits=LIMITS)


@pytest.mark.parametrize("blob", [1, 12])
def test_header_original_and_canonical_byte_bounds(blob: int) -> None:
    """Original or expanded canonical JSON must fit the same explicit byte policy."""
    raw = b'{"a":1e-6}'
    with pytest.raises(ValueError):
        header_digest(raw, limits=Limits(64, blob, 64, 8, 8, 8))


def test_canonical_json_document_bound_is_not_reset_or_replaced() -> None:
    """An expanded Common representation cannot escape the original document ceiling."""
    raw = b'{"a":1e-6}'
    with pytest.raises(ValueError):
        header_digest(raw, limits=Limits(len(raw), 64, 64, 8, 8, 8))
    with pytest.raises(ConfigurationError):
        index_digest((), max_rows=1, max_index_bytes=2, limits=Limits(True, 64, 64, 8, 8, 8))


@pytest.mark.parametrize(
    ("previous", "chunk"),
    [
        ("sha256:" + "0" * 63, "sha256:" + "1" * 64),
        ("sha256:" + "A" * 64, "sha256:" + "1" * 64),
        ("sha256:" + "0" * 64, "1" * 64),
        (None, "sha256:" + "1" * 64),
    ],
)
def test_malformed_complete_digest_declarations_refuse(previous: str, chunk: str) -> None:
    """No missing algorithm, uppercase, null or shortened digest acquires chain meaning."""
    with pytest.raises(ValueError):
        fold_chain(previous, chunk)


def test_index_hashes_every_actual_row_once_in_original_order() -> None:
    """A real single-pass source is folded without buffering or sorting its population."""
    pending = list(ROWS)

    def rows() -> Iterator[bytes]:
        """Consume each original bounded row exactly once."""
        while pending:
            yield pending.pop(0)

    canonical = (
        b"["
        + b",".join(
            json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode()
            for raw in ROWS
        )
        + b"]"
    )
    assert index_digest(rows(), max_rows=2, max_index_bytes=512, limits=LIMITS) == independent_sha(
        b"slog.index.v1\x00" + canonical
    )
    assert not pending
    assert index_digest((), max_rows=1, max_index_bytes=2, limits=LIMITS) == (
        independent_sha(b"slog.index.v1\x00[]")
    )
    assert index_digest(
        reversed(ROWS), max_rows=2, max_index_bytes=512, limits=LIMITS
    ) != independent_sha(b"slog.index.v1\x00" + canonical)


@pytest.mark.parametrize(
    ("rows", "maximum_rows", "maximum_bytes"),
    [
        (ROWS, 1, 512),
        (ROWS, 2, 20),
        (ROWS, 0, 512),
        (ROWS, True, 512),
        (ROWS, 2, False),
        ((), 1, 1),
        (("not bytes",), 1, 64),
        ((b'{"v":1e-6}',), 1, 12),
        ((b"[]",), 1, 8),
    ],
)
def test_index_cumulative_native_limits(
    rows: tuple[bytes, ...], maximum_rows: int, maximum_bytes: int
) -> None:
    """Raw and canonical totals, delimiters, counts and row kinds cannot reset the budget."""
    with pytest.raises(ValueError):
        index_digest(rows, max_rows=maximum_rows, max_index_bytes=maximum_bytes, limits=LIMITS)


@pytest.mark.parametrize("value", [9007199254740991, -9007199254740991, 0])
def test_original_safe_integer_boundary_keeps_its_exact_preimage(value: int) -> None:
    """The exact safe endpoints survive Common binary64 and native token checks."""
    raw = ('{"counter":' + str(value) + "}").encode()
    assert header_digest(raw, limits=LIMITS) == independent_sha(b"slog.header.v1\x00" + raw)
