# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — complete local wheel member and installed byte identity

"""Verify hash-bound local wheels without extracting or executing their contents."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
import stat
import zipfile
import zlib
from importlib.metadata import Distribution
from pathlib import Path, PurePosixPath

from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename

from .inputs import Json, read_bytes, root_directory
from .limits import MAX_ENTRIES, MAX_FILE, MAX_TREE
from .reports import Fault


def _member(name: str) -> bool:
    """Check one portable relative archive member spelling before path access."""
    parts = PurePosixPath(name).parts
    return (
        bool(parts)
        and not name.startswith("/")
        and "\\" not in name
        and "\x00" not in name
        and all(part not in ("", ".", "..") for part in name.split("/"))
        and PurePosixPath(name).as_posix() == name
    )


def product_files(root: Path) -> set[str]:
    """Enumerate bounded regular product files, refusing links and special entries.

    Parameters
    ----------
    root : Path
        Independently selected native package or source namespace.

    Returns
    -------
    set[str]
        Relative files, excluding only the standard generated __pycache__ directory.

    Raises
    ------
    Fault
        Raised for unavailable, linked, special or oversized namespace populations.
    """
    root = root_directory(str(root))
    pending = [root]
    result: set[str] = set()
    count = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_ENTRIES:
                        raise Fault("resource_limit")
                    path = Path(entry.path)
                    if entry.is_symlink():
                        raise Fault("source_identity_mismatch", path.name)
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name != "__pycache__":
                            pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        result.add(path.relative_to(root).as_posix())
                    else:
                        raise Fault("source_identity_mismatch", path.name)
        except OSError as error:
            raise Fault("input_unavailable", exit_code=3) from error
    return result


def wheel_members(
    directory: Path, artifact: dict[str, Json], distribution: Distribution, *, namespace: str
) -> dict[str, bytes]:
    """Check the complete selected ZIP, RECORD and native installed member bytes.

    Parameters
    ----------
    directory : Path
        Independently chosen artifact directory. The descriptor names one regular leaf.
    artifact : dict[str, Json]
        Exact filename, byte length, SHA-256 and bdist_wheel kind; no download URL.
    distribution : Distribution
        Actual selected native distribution, never imported wheel code.
    namespace : str
        Independently selected package directory; it need not equal the distribution name.

    Returns
    -------
    dict[str, bytes]
        Complete verified file population, including RECORD. Empty structural
        directory entries are validated and counted in the archive-entry budget.

    Raises
    ------
    Fault
        Raised for unavailable, malformed, oversized or inconsistent original inputs.
    """
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", namespace) is None:
        raise Fault("configuration_invalid", "local-wheel-namespace", 4)
    if (
        set(artifact) != {"filename", "bytes", "sha256", "kind"}
        or artifact["kind"] != "bdist_wheel"
        or not isinstance(artifact["filename"], str)
        or "/" in artifact["filename"]
        or not _member(artifact["filename"])
        or type(artifact["bytes"]) is not int
        or not 0 < artifact["bytes"] <= MAX_FILE
        or not isinstance(artifact["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]) is None
    ):
        raise Fault("configuration_invalid", "local-wheel", 4)
    filename = artifact["filename"]
    data = read_bytes(directory, filename, MAX_FILE)
    if len(data) != artifact["bytes"] or hashlib.sha256(data).hexdigest() != artifact["sha256"]:
        raise Fault("source_identity_mismatch", filename)
    try:
        name, version, _, _ = parse_wheel_filename(filename)
    except InvalidWheelFilename as error:
        raise Fault("configuration_invalid", filename, 4) from error
    native_name = distribution.metadata.get("Name")
    if (
        not isinstance(native_name, str)
        or name != canonicalize_name(native_name)
        or str(version) != distribution.version
    ):
        raise Fault("source_identity_mismatch", filename)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if (
                not entries
                or len(entries) > MAX_ENTRIES
                or len({entry.filename for entry in entries}) != len(entries)
                or sum(entry.file_size for entry in entries) > MAX_TREE
            ):
                raise Fault("source_identity_mismatch", filename)
            members: dict[str, bytes] = {}
            for entry in entries:
                directory_entry = entry.is_dir()
                member_name = entry.filename[:-1] if directory_entry else entry.filename
                expected_mode = stat.S_IFDIR if directory_entry else stat.S_IFREG
                if (
                    not _member(member_name)
                    or entry.flag_bits & 1
                    or stat.S_IFMT(entry.external_attr >> 16) not in (0, expected_mode)
                    or entry.file_size > MAX_FILE
                    or (directory_entry and entry.file_size != 0)
                ):
                    raise Fault("source_identity_mismatch", filename)
                if directory_entry:
                    continue
                members[entry.filename] = archive.read(entry)
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError, zlib.error) as error:
        raise Fault("source_identity_mismatch", filename) from error
    metadata_names = [name for name in members if name.endswith(".dist-info/METADATA")]
    if len(metadata_names) != 1:
        raise Fault("source_identity_mismatch", filename)
    metadata_name = metadata_names[0]
    prefix = metadata_name.removesuffix("METADATA")
    record_name = prefix + "RECORD"
    if record_name not in members or prefix + "WHEEL" not in members:
        raise Fault("source_identity_mismatch", filename)
    try:
        rows = list(csv.reader(io.StringIO(members[record_name].decode("utf-8")), strict=True))
    except (UnicodeError, csv.Error) as error:
        raise Fault("source_identity_mismatch", filename) from error
    if (
        len(rows) != len(members)
        or any(len(row) != 3 for row in rows)
        or {row[0] for row in rows} != set(members)
    ):
        raise Fault("source_identity_mismatch", filename)
    site = Path(str(distribution.locate_file("")))
    for path, recorded_hash, recorded_size in rows:
        if path == record_name:
            if recorded_hash or recorded_size:
                raise Fault("source_identity_mismatch", filename)
            continue
        original = members[path]
        digest = base64.urlsafe_b64encode(hashlib.sha256(original).digest()).rstrip(b"=").decode()
        if recorded_hash != "sha256=" + digest or recorded_size != str(len(original)):
            raise Fault("source_identity_mismatch", filename)
        installed = read_bytes(site, path, MAX_FILE)
        if installed != original:
            raise Fault("source_identity_mismatch", path)
    expected_product = {
        path.removeprefix(namespace + "/") for path in members if path.startswith(namespace + "/")
    }
    if product_files(site / namespace) != expected_product:
        raise Fault("source_identity_mismatch", namespace)
    return members
