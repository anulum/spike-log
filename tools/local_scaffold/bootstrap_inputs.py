# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — read-only environment input verification

"""Validate every frozen bootstrap operand without imports, downloads or writes."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from .bootstrap_bindings import MAX_ARTIFACT_BYTES, PYTHON_VERSION, SOURCE_PINS
from .inputs import Json, decode, parse_json, read_bytes, relative_path
from .limits import MAX_FILE, MAX_INPUT, MAX_TREE
from .reports import Fault


@dataclass(slots=True)
class _Reader:
    """Count actual input bytes across the complete operation.

    Parameters
    ----------
    limit : int
        Caller ceiling bounded by the fixed whole-operation maximum.

    Attributes
    ----------
    consumed : int
        Cumulative bytes read, never reset between package or owner inputs.
    """

    limit: int
    consumed: int = field(init=False, default=0)

    def read(self, root: Path, name: str, limit: int) -> bytes:
        """Read regular no-follow input bytes under the remaining operation budget.

        Parameters
        ----------
        root : Path
            Independently selected data root.
        name : str
            Relative input path, never an executable selector.
        limit : int
            Fixed per-input ceiling.

        Returns
        -------
        bytes
            Complete original bytes after path, kind and budget admission.
        """
        data = read_bytes(root, name, min(limit, self.limit - self.consumed))
        self.consumed += len(data)
        return data

    def pinned(
        self,
        root: Path,
        name: str,
        digest: str,
        size: int | None = None,
        *,
        limit: int = MAX_ARTIFACT_BYTES,
    ) -> bytes:
        """Require an independently selected whole-file digest and optional length.

        Parameters
        ----------
        root : Path
            Independent root supplying immutable input data.
        name : str
            Safe relative file name.
        digest : str
            Expected SHA-256 selected by trusted source, not received data.
        size : int | None
            Expected complete byte length when declared.
        limit : int
            Fixed input ceiling within the cumulative operation budget.

        Returns
        -------
        bytes
            Original bytes matching the complete selected identity.

        Raises
        ------
        Fault
            An input is unavailable, unsafe, over budget or does not match.
        """
        data = self.read(root, name, limit)
        if (size is not None and len(data) != size) or hashlib.sha256(data).hexdigest() != digest:
            raise Fault("source_identity_mismatch", name)
        return data


def _target(root: Path, raw: str, artifacts: Path, owner: Path, reader: _Reader) -> None:
    """Check the selected destination without creating or executing it.

    Parameters
    ----------
    root : Path
        Inspected repository root.
    raw : str
        Explicit operator-selected environment destination.
    artifacts, owner : Path
        Read-only input trees that must not contain the destination.
    reader : _Reader
        Shared byte budget for an existing environment configuration.

    Raises
    ------
    Fault
        The destination is linked, overlaps input trees, or is an incompatible
        or nonempty uninitialised environment directory.
    """
    target = Path(os.path.abspath(root / raw))
    try:
        relative_path(Path(target.anchor), target.relative_to(target.anchor).as_posix())
    except Fault as fault:
        raise Fault(fault.code, "environment", fault.exit_code) from None
    if any(
        target.is_relative_to(tree) or tree.is_relative_to(target) for tree in (artifacts, owner)
    ):
        raise Fault("policy_refusal", "environment")
    if not target.exists():
        return
    if not target.is_dir():
        raise Fault("input_unavailable", "environment", 3)
    configuration = target / "pyvenv.cfg"
    if not configuration.exists():
        if any(target.iterdir()):
            raise Fault("input_unavailable", "environment", 3)
        return
    relative_path(target, "bin")
    if not (target / "bin/python").samefile(Path(sys.executable)):
        raise Fault("dependency_alignment.incompatible-patch", "environment")
    text = decode(reader.read(target, "pyvenv.cfg", MAX_INPUT), "environment")
    for name, expected in (
        ("version_info", PYTHON_VERSION),
        ("implementation", "CPython"),
        ("include-system-site-packages", "false"),
    ):
        values = re.findall(r"(?m)^" + name + r"[ \t]*=[ \t]*([^\r\n]+?)[ \t]*$", text)
        if values != [expected]:
            raise Fault("dependency_alignment.incompatible-patch", "environment")


def verify(
    root: Path,
    artifacts: Path,
    owner: Path,
    environment: str,
    *,
    max_input_bytes: int = MAX_TREE,
) -> None:
    """Require the complete frozen source and artifact set before bootstrap writes.

    Parameters
    ----------
    root : Path
        Independently selected repository supplying the exact frozen lock inputs.
    artifacts : Path
        Explicit flat directory of all original selected package artifacts,
        local source response files, owner manifest and build evidence.
    owner : Path
        Independently selected Common owning source tree; never inferred from a response.
    environment : str
        Operator-selected destination, inspected only as data.
    max_input_bytes : int
        Positive inherited read ceiling, at most the fixed complete-operation cap.

    Returns
    -------
    None
        All current operands match. This is input readiness, not an installed
        producer, owner-source, security, scientific or publication admission.

    Raises
    ------
    Fault
        Runtime, destination, source, artifact or resource requirements refuse.
        No file, directory, cache, environment, process or network is created.
    """
    if (
        platform.python_version() != PYTHON_VERSION
        or sys.implementation.name != "cpython"
        or sys.platform != "linux"
        or platform.machine() != "x86_64"
    ):
        raise Fault("dependency_alignment.incompatible-patch", "environment")
    if type(max_input_bytes) is not int or not 0 < max_input_bytes <= MAX_TREE:
        raise Fault("configuration_invalid", "max-input-bytes", 4)
    reader = _Reader(max_input_bytes)
    _target(root, environment, artifacts, owner, reader)
    source_bytes: dict[str, bytes] = {}
    for name, digest in SOURCE_PINS.items():
        source_bytes[name] = reader.pinned(root, name, digest, limit=MAX_INPUT)
    baseline = cast(dict[str, Json], parse_json(source_bytes["dependency-provenance.json"]))
    packages = cast(list[dict[str, Json]], baseline["packages"])
    for package in packages:
        artifact = cast(dict[str, Json], package["source_artifact"])
        reader.pinned(
            artifacts,
            cast(str, artifact["filename"]),
            cast(str, artifact["sha256"]),
            cast(int, artifact["bytes"]),
        )
    verified_manifests: set[str] = set()
    for package in packages:
        if "owner_source" not in package:
            continue
        response_name = cast(str, package["name"]) + ".json"
        response_bytes = reader.pinned(
            artifacts, response_name, cast(str, package["source_input_sha256"]), limit=MAX_INPUT
        )
        response = cast(dict[str, Json], parse_json(response_bytes))
        source = cast(dict[str, Json], package["owner_source"])
        manifest_ref = cast(dict[str, Json], response["owner_manifest"])
        expected = cast(dict[str, Json], source["manifest"])
        manifest_bytes = reader.pinned(
            artifacts,
            cast(str, manifest_ref["path"]),
            cast(str, expected["sha256"]),
            cast(int, expected["bytes"]),
            limit=MAX_INPUT,
        )
        manifest_digest = cast(str, expected["sha256"])
        if manifest_digest not in verified_manifests:
            manifest = cast(dict[str, Json], parse_json(manifest_bytes))
            for item in cast(list[dict[str, Json]], manifest["files"]):
                reader.pinned(
                    owner,
                    cast(str, item["path"]),
                    cast(str, item["sha256"]),
                    cast(int, item["bytes"]),
                    limit=MAX_FILE,
                )
            verified_manifests.add(manifest_digest)
        for received, selected in zip(
            cast(list[dict[str, Json]], response["build_inputs"]),
            cast(list[dict[str, Json]], source["build_inputs"]),
            strict=True,
        ):
            reader.pinned(
                artifacts,
                cast(str, received["path"]),
                cast(str, selected["sha256"]),
                cast(int, selected["bytes"]),
            )
