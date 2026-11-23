# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance
"""Admit the vendored provenance snapshot's responses only by the digests the provenance pins."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

from .inputs import Json, json_object, read_bytes

SNAPSHOT = "vendor/provenance-inputs/"
"""Tracked complete source snapshot: the original registry responses and the owner-source records."""

SECTIONS = ("registry", "local")
"""Snapshot subdirectories: original registry responses, and owner-source response records."""


def is_snapshot_response(name: str) -> bool:
    """Return whether a tracked filename is one response of the vendored provenance snapshot.

    Parameters
    ----------
    name : str
        Tracked repository-relative filename.

    Returns
    -------
    bool
        ``True`` only for ``vendor/provenance-inputs/<registry|local>/<file>.json``. Such a file
        holds third-party or recorded bytes that are pinned, never scanned or licensed as authored text.
    """
    parts = name.removeprefix(SNAPSHOT).split("/")
    return (
        name.startswith(SNAPSHOT)
        and len(parts) == 2
        and parts[0] in SECTIONS
        and parts[1].endswith(".json")
    )


def pinned_response(root: Path, name: str) -> bool:
    """Return whether the snapshot index and the dependency provenance both pin these bytes.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Tracked snapshot response filename, as accepted by :func:`is_snapshot_response`.

    Returns
    -------
    bool
        ``True`` when exactly one index entry names this file with its SHA-256, and the provenance
        record of that entry's package pins the same digest: ``official_metadata_sha256`` for a
        registry package, ``source_input_sha256`` for an owner-source package.
    """
    digest = hashlib.sha256(read_bytes(root, name)).hexdigest()
    index = json_object(root, SNAPSHOT + "inputs.json")
    entries = [
        entry
        for entry in cast(list[Json], index.get("packages", []))
        if isinstance(entry, dict) and entry.get("path") == name.removeprefix(SNAPSHOT)
    ]
    if len(entries) != 1 or entries[0].get("sha256") != digest:
        return False
    packages = cast(
        list[dict[str, Json]], json_object(root, "dependency-provenance.json")["packages"]
    )
    records = [package for package in packages if package["name"] == entries[0].get("name")]
    if len(records) != 1:
        return False
    key = "source_input_sha256" if "source_kind" in records[0] else "official_metadata_sha256"
    return records[0].get(key) == digest
