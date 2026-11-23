# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance
"""Admit the vendored local wheels only by the exact bytes the dependency provenance selects."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

from .inputs import Json, json_object, read_bytes
from .provenance_local import LOCAL_KINDS

VENDORED = "vendor/environment-inputs/"
"""Tracked directory of the local package wheels and the records that bind them."""


def is_vendored_wheel(name: str) -> bool:
    """Return whether a tracked filename is a wheel directly under the vendored directory.

    Parameters
    ----------
    name : str
        Tracked repository-relative filename.

    Returns
    -------
    bool
        ``True`` only for ``vendor/environment-inputs/<file>.whl``; such a file is binary and
        is never scanned as text.
    """
    filename = name.removeprefix(VENDORED)
    return name.startswith(VENDORED) and "/" not in filename and filename.endswith(".whl")


def selected_by_provenance(root: Path, name: str) -> bool:
    """Return whether the dependency provenance selects exactly this vendored wheel's bytes.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Tracked vendored wheel filename, as accepted by :func:`is_vendored_wheel`.

    Returns
    -------
    bool
        ``True`` when exactly one local package of ``dependency-provenance.json`` names this
        wheel as its source artifact with the same byte count and SHA-256.

    Notes
    -----
    The reviewed provenance pins these bytes, so their licence and content are established by
    that record and the REUSE annotations rather than by a text scan.
    """
    filename = name.removeprefix(VENDORED)
    data = read_bytes(root, name)
    actual = {
        "bytes": len(data),
        "filename": filename,
        "kind": "bdist_wheel",
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    packages = cast(
        list[dict[str, Json]], json_object(root, "dependency-provenance.json")["packages"]
    )
    selected = [
        package["source_artifact"]
        for package in packages
        if package.get("source_kind") in LOCAL_KINDS
        and cast(dict[str, Json], package["source_artifact"])["filename"] == filename
    ]
    return selected == [actual]
