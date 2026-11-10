# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Bounded reads and strict offline parsing of untrusted repository inputs."""

from __future__ import annotations

import json
import math
import os
import re
import stat
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import cast

from .policy import MAX_DEPTH, MAX_INPUT, MAX_STRING, MAX_VALUES
from .reports import Fault, safe_location

type Json = None | bool | int | float | str | list[Json] | dict[str, Json]

INVALID_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
SURROGATE = re.compile(r"[\ud800-\udfff]")
JSON_TOKENS = re.compile(r'"(?:[^"\\]|\\[\s\S])*+"?|[{}\[\]]|[^\s{}\[\]":,]+')


def root_directory(raw: str) -> Path:
    """Validate the root and each ancestor without following symbolic links.

    Parameters
    ----------
    raw : str
        Caller root path, normalised absolutely while retaining symlink checks on every ancestor.

    Returns
    -------
    Path
        Absolute existing directory with no symbolic-link ancestor.

    Raises
    ------
    Fault
        Raised as root_symlink or unavailable root; received path bytes are not emitted.
    """
    root = Path(os.path.abspath(raw))
    try:
        for component in [*reversed(root.parents), root]:
            if stat.S_ISLNK(component.lstat().st_mode):
                raise Fault("root_symlink")
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise Fault("root_unavailable", exit_code=3)
    except OSError as error:
        raise Fault("root_unavailable", exit_code=3) from error
    return root


def relative_path(root: Path, name: str) -> Path:
    """Reject unsafe names and symbolic ancestors before reading a local file.

    Parameters
    ----------
    root : Path
        Validated repository root beneath which the lexical name is inspected.
    name : str
        Safe relative scalar-Unicode name; absolute paths, parent traversal and symbolic ancestors are refused.

    Returns
    -------
    Path
        Lexical path beneath root, retaining ancestors for no-follow checks; a missing final file is not created.

    Raises
    ------
    Fault
        Raised for policy refusal, symbolic ancestors or unavailable ancestor metadata.
    """
    if safe_location(name) != name:
        raise Fault("policy_refusal")
    current = root
    for part in PurePosixPath(name).parts:
        current /= part
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise Fault("repository_inventory.symlink-entry", name)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise Fault("input_unavailable", name, 3) from error
    return current


def require_byte_budget(size: int, limit: int, location: str | None = None) -> None:
    """Apply the same byte cap before allocation, after reading and before parsing.

    Parameters
    ----------
    size : int
        Observed file, buffer or input byte count before allocation/after reading.
    limit : int
        Inclusive maximum permitted byte count.
    location : str | None
        Optional lexical input location used for a safe diagnostic; received values are never echoed.

    Raises
    ------
    Fault
        Raised as resource_limit only when size exceeds limit.
    """
    if size > limit:
        raise Fault("resource_limit", location)


def read_bytes(root: Path, name: str, limit: int = MAX_INPUT) -> bytes:
    """Read a bounded regular file through held no-follow directory descriptors.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Relative file opened nonblocking with O_NOFOLLOW beneath held no-follow directories.
    limit : int
        Inclusive cap checked against descriptor size and final bytes; default MAX_INPUT.

    Returns
    -------
    bytes
        Complete original file contents after bounded regular-kind and no-follow admission.

    Raises
    ------
    Fault
        Raised for unavailable input, unsafe path/kind or byte-budget overflow.
    """
    path = Path(os.path.abspath(relative_path(root, name)))
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        with ExitStack() as opened:
            parent = os.open(path.anchor, directory_flags)
            opened.callback(os.close, parent)
            for component in path.parts[1:-1]:
                parent = os.open(component, directory_flags, dir_fd=parent)
                opened.callback(os.close, parent)
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
            opened.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise Fault("repository_inventory.special-file", name)
            require_byte_budget(info.st_size, limit, name)
            data = bytearray()
            while len(data) <= limit:
                block = os.read(descriptor, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            require_byte_budget(len(data), limit, name)
            return bytes(data)
    except OSError as error:
        raise Fault("input_unavailable", name, 3) from error


def decode(data: bytes, location: str | None = None) -> str:
    """Decode scalar UTF-8 while denying terminal-control and surrogate bytes.

    Parameters
    ----------
    data : bytes
        Retained input bytes decoded strictly as UTF-8.
    location : str | None
        Optional lexical input location used for a safe diagnostic; received values are never echoed.

    Returns
    -------
    str
        Decoded text without disallowed terminal-control bytes.

    Raises
    ------
    Fault
        Raised as input_encoding_invalid or input_unicode_invalid for rejected input.
    """
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise Fault("input_encoding_invalid", location) from error
    if INVALID_CONTROL.search(text):
        raise Fault("input_unicode_invalid", location)
    return text


def read_text(root: Path, name: str, limit: int = MAX_INPUT) -> str:
    """Read a finite UTF-8 source/configuration file with safe failure semantics.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Relative UTF-8 regular-file input.
    limit : int
        Inclusive read byte cap passed unchanged to read_bytes.

    Returns
    -------
    str
        Admitted original text after bounded no-follow read and strict decoding.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable input, byte overflow or invalid encoding/control characters.
    """
    return decode(read_bytes(root, name, limit), name)


def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Construct a JSON object only when every member name is unique.

    Parameters
    ----------
    pairs : list[tuple[str, object]]
        Ordered decoded JSON member pairs supplied by the native object-pairs hook.

    Returns
    -------
    dict[str, object]
        Original members retained exactly once; no last-key-wins replacement.

    Raises
    ------
    Fault
        Raised as duplicate_member for any repeated decoded key.
    """
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise Fault("duplicate_member")
        output[key] = value
    return output


def nonfinite_constant(_: str) -> None:
    """Refuse the non-JSON NaN and Infinity extension without echoing it.

    Parameters
    ----------
    _ : str
        Native JSON extension token, deliberately unused and never reflected.

    Raises
    ------
    Fault
        Always raised as policy_refusal for NaN/Infinity extensions.
    """
    raise Fault("policy_refusal")


def validate_value(value: object, location: str | None = None) -> Json:
    """Check finite scalar Unicode, type, depth, string and total-value limits.

    Parameters
    ----------
    value : object
        Decoded candidate traversed iteratively, including dictionary keys and values.
    location : str | None
        Optional lexical input location used for a safe diagnostic; received values are never echoed.

    Returns
    -------
    Json
        The same finite admitted JSON-compatible object, without coercion or mutation.

    Raises
    ------
    Fault
        Raised for excessive depth/population/string bytes, invalid Unicode, non-string keys or unsupported/nonfinite values.
    """
    pending: list[tuple[object, int]] = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > MAX_VALUES:
            raise Fault("resource_limit", location)
        if isinstance(item, str):
            if SURROGATE.search(item):
                raise Fault("input_unicode_invalid", location)
            if INVALID_CONTROL.search(item):
                raise Fault("input_unicode_invalid", location)
            if len(item.encode("utf-8")) > MAX_STRING:
                raise Fault("resource_limit", location)
        elif isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise Fault("policy_refusal", location)
            pending.extend((x, depth + 1) for pair in item.items() for x in pair)
        elif isinstance(item, list):
            pending.extend((x, depth + 1) for x in item)
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise Fault("policy_refusal", location)
        elif item is not None and not isinstance(item, (bool, int)):
            raise Fault("policy_refusal", location)
    return cast(Json, value)


def parse_json(data: bytes, location: str | None = None) -> Json:
    """Parse bounded strict JSON without remote references or parser extensions.

    Parameters
    ----------
    data : bytes
        Original JSON bytes checked for input/token/depth budgets before native parsing.
    location : str | None
        Optional lexical input location used for a safe diagnostic; received values are never echoed.

    Returns
    -------
    Json
        Strict finite parsed JSON; duplicate members and nonfinite extensions are not admitted.

    Raises
    ------
    Fault
        Raised for bounded-input, UTF-8/Unicode, syntax or decoded-value refusal.
    """
    require_byte_budget(len(data), MAX_INPUT, location)
    text = decode(data, location)
    depth, values = 0, 0
    for match in JSON_TOKENS.finditer(text):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            values += 1
        elif token in ("]", "}"):
            depth -= 1
        else:
            values += 1
        if depth > MAX_DEPTH or values > MAX_VALUES:
            raise Fault("resource_limit", location)
    try:
        value: object = json.loads(
            text, object_pairs_hook=unique_pairs, parse_constant=nonfinite_constant
        )
    except (ValueError, RecursionError) as error:
        raise Fault("policy_refusal", location) from error
    return validate_value(value, location)


def json_object(root: Path, name: str) -> dict[str, Json]:
    """Read a strict JSON object, retaining the fixed input's lexical location.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Relative strict JSON file whose top-level value must be an object.

    Returns
    -------
    dict[str, Json]
        Admitted decoded object with its lexical input location retained in failures.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable bytes, invalid JSON or a non-object root.
    """
    value = parse_json(read_bytes(root, name), name)
    if not isinstance(value, dict):
        raise Fault("policy_refusal", name)
    return value


def yaml_object(root: Path, name: str, workflow: bool = False) -> dict[str, Json]:
    """Parse finite safe YAML after checking tokens, aliases, tags and depth.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Relative safe-YAML input whose top-level value must be a mapping.
    workflow : bool
        Apply the tighter 102400-byte workflow limit and workflow parser controls when true.

    Returns
    -------
    dict[str, Json]
        Finite string-keyed mapping after native safe-YAML validation.

    Raises
    ------
    Fault
        Raised for unavailable/unsafe input, resource/alias/tag/duplicate/shape or Unicode refusal.
    """
    data = read_bytes(root, name, 102400 if workflow else MAX_INPUT)
    return parse_yaml(data, name, workflow)


def parse_yaml(data: bytes, name: str, workflow: bool = False) -> dict[str, Json]:
    """Parse retained safe YAML while keeping missing tooling inside CLI recovery.

    Parameters
    ----------
    data : bytes
        Retained YAML bytes passed to the lazily imported native parser.
    name : str
        Lexical location for authored input diagnostics.
    workflow : bool
        Enable the workflow-specific byte and line limits.

    Returns
    -------
    dict[str, Json]
        Parsed finite safe-YAML mapping without executing received constructors.

    Raises
    ------
    Fault
        Raised for the native bounded YAML refusal contract; missing parser tooling propagates to CLI recovery.
    """
    from .yaml_inputs import parse_yaml as parse

    return parse(data, name, workflow)
