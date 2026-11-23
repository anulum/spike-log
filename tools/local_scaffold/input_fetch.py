# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Acquire every selected environment artifact from its one pinned origin into a new directory."""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import shutil
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .bootstrap_bindings import MAX_ARTIFACT_BYTES
from .inputs import Json, json_object, read_bytes, relative_path, root_directory
from .processes import run_process
from .reports import Fault

REGISTRY_HOST: Final = "files.pythonhosted.org"
_REGISTRY_URL: Final = re.compile(
    r"https://files\.pythonhosted\.org"
    r"(/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/([A-Za-z0-9][A-Za-z0-9._+-]*))"
)
_FILENAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
_DIGEST: Final = re.compile(r"[0-9a-f]{64}")
_REGISTRY_KINDS: Final = frozenset({"bdist_wheel", "sdist"})
VENDORED: Final = "vendor/environment-inputs/"
"""Tracked directory of the local package wheels and the records that bind them."""
_PROVENANCE: Final = "dependency-provenance.json"
_CHUNK: Final = 65536


@dataclass(frozen=True, slots=True)
class Artifact:
    """One selected artifact and the single origin it may be taken from.

    Attributes
    ----------
    filename : str
        Flat destination name; for a registry origin also the final request path segment.
    size : int
        Pinned complete byte length.
    sha256 : str
        Pinned SHA-256 of the complete bytes.
    origin : str
        Request path on the registry host, or the repository-relative tracked file.
    tracked : bool
        True when the origin is a tracked repository file rather than the registry.
    """

    filename: str
    size: int
    sha256: str
    origin: str
    tracked: bool


def _artifact(package: Json) -> Artifact:
    """Admit one package's selected artifact only under the fixed origin rules.

    Parameters
    ----------
    package : Json
        One received ``packages`` member of the dependency provenance.

    Returns
    -------
    Artifact
        The pinned identity and its one admitted origin.

    Raises
    ------
    Fault
        ``policy_refusal`` for any other shape, kind, name, size, digest or origin. A
        registry origin must be HTTPS on exactly the registry host, with no credentials,
        port, query or fragment, and a request path ending in the artifact's own name.
    """
    source = package.get("source_artifact") if isinstance(package, dict) else None
    if not isinstance(source, dict):
        raise Fault("policy_refusal", _PROVENANCE)
    filename, size, digest = source.get("filename"), source.get("bytes"), source.get("sha256")
    if not (
        isinstance(filename, str)
        and _FILENAME.fullmatch(filename)
        and type(size) is int
        and 0 < size <= MAX_ARTIFACT_BYTES
        and isinstance(digest, str)
        and _DIGEST.fullmatch(digest)
    ):
        raise Fault("policy_refusal", _PROVENANCE)
    kind, url, path = source.get("kind"), source.get("url"), source.get("path")
    if not isinstance(kind, str) or kind not in _REGISTRY_KINDS or path is not None:
        raise Fault("policy_refusal", _PROVENANCE)
    if isinstance(package, dict) and "source_kind" in package:
        if url is not None:
            raise Fault("policy_refusal", _PROVENANCE)
        return Artifact(filename, size, digest, VENDORED + filename, True)
    match = _REGISTRY_URL.fullmatch(url) if isinstance(url, str) else None
    if match is None or match.group(2) != filename:
        raise Fault("policy_refusal", _PROVENANCE)
    return Artifact(filename, size, digest, match.group(1), False)


def _reference(value: Json) -> Artifact:
    """Admit one record reference of a local package's response record.

    Parameters
    ----------
    value : Json
        One ``owner_manifest`` or ``build_inputs`` member: a flat name, byte count and digest.

    Returns
    -------
    Artifact
        The referenced vendored file, tracked under :data:`VENDORED`.

    Raises
    ------
    Fault
        ``policy_refusal`` for any other shape, name, size or digest.
    """
    if not isinstance(value, dict) or set(value) != {"bytes", "path", "sha256"}:
        raise Fault("policy_refusal", _PROVENANCE)
    name, size, digest = value["path"], value["bytes"], value["sha256"]
    if not (
        isinstance(name, str)
        and _FILENAME.fullmatch(name)
        and type(size) is int
        and 0 < size <= MAX_ARTIFACT_BYTES
        and isinstance(digest, str)
        and _DIGEST.fullmatch(digest)
    ):
        raise Fault("policy_refusal", _PROVENANCE)
    return Artifact(name, size, digest, VENDORED + name, True)


def _records(root: Path, package: dict[str, Json]) -> list[Artifact]:
    """Admit a local package's response record and every record it references.

    Parameters
    ----------
    root : Path
        Validated repository root supplying the vendored records.
    package : dict[str, Json]
        One local package of the dependency provenance, carrying ``source_input_sha256``.

    Returns
    -------
    list[Artifact]
        The response record, pinned by ``source_input_sha256``, then its owner manifest and
        build inputs, pinned by the response record's own references.

    Raises
    ------
    Fault
        A missing pin, a response record of other bytes, or a refused reference.
    """
    name, digest = package.get("name"), package.get("source_input_sha256")
    if not (isinstance(name, str) and _FILENAME.fullmatch(name + ".json")):
        raise Fault("policy_refusal", _PROVENANCE)
    if not (isinstance(digest, str) and _DIGEST.fullmatch(digest)):
        raise Fault("policy_refusal", _PROVENANCE)
    data = read_bytes(root, VENDORED + name + ".json", MAX_ARTIFACT_BYTES)
    response = Artifact(name + ".json", len(data), digest, VENDORED + name + ".json", True)
    _verified(response, data)
    value = json_object(root, VENDORED + name + ".json")
    references = value.get("build_inputs")
    if not isinstance(references, list):
        raise Fault("policy_refusal", _PROVENANCE)
    return [response, _reference(value.get("owner_manifest")), *map(_reference, references)]


def selected(root: Path) -> list[Artifact]:
    """Read every selected artifact from the repository's dependency provenance.

    Parameters
    ----------
    root : Path
        Validated repository root supplying ``dependency-provenance.json`` as data.

    Returns
    -------
    list[Artifact]
        Every package's selected artifact, in provenance order, then each local package's
        vendored response record and the records it references, with unique names; a record
        two local packages share is selected once.

    Raises
    ------
    Fault
        An unreadable provenance, a refused artifact, or a repeated destination name.
    """
    packages = json_object(root, _PROVENANCE).get("packages")
    if not isinstance(packages, list) or not packages:
        raise Fault("policy_refusal", _PROVENANCE)
    artifacts: list[Artifact] = []
    for package in packages:
        artifact = _artifact(package)
        if any(known.filename == artifact.filename for known in artifacts):
            raise Fault("duplicate_member", _PROVENANCE)
        artifacts.append(artifact)
    for package in packages:
        if isinstance(package, dict) and "source_kind" in package:
            for record in _records(root, package):
                if record in artifacts:
                    continue
                if any(known.filename == record.filename for known in artifacts):
                    raise Fault("duplicate_member", _PROVENANCE)
                artifacts.append(record)
    return artifacts


def _verified(artifact: Artifact, data: bytes) -> bytes:
    """Require the complete pinned length and digest.

    Parameters
    ----------
    artifact : Artifact
        Pinned identity selected by the repository, not by the received bytes.
    data : bytes
        Complete received or read bytes, at most one byte over the pinned length.

    Returns
    -------
    bytes
        The same bytes, after both identities match.

    Raises
    ------
    Fault
        ``source_identity_mismatch`` for any other length or digest.
    """
    if len(data) != artifact.size or hashlib.sha256(data).hexdigest() != artifact.sha256:
        raise Fault("source_identity_mismatch", artifact.filename)
    return data


def _tracked(root: Path, artifact: Artifact) -> bytes:
    """Read a tracked regular repository file without following links.

    Parameters
    ----------
    root : Path
        Validated repository root whose own Git index decides tracking.
    artifact : Artifact
        Pinned identity of the file; its origin is a safe relative path, and traversal,
        linked ancestors and untracked files are refused.

    Returns
    -------
    bytes
        Complete bytes matching the pinned identity.

    Raises
    ------
    Fault
        An unsafe or untracked path, an unreadable file, or a different identity.
    """
    name = artifact.origin
    relative_path(root, name)
    observed = run_process(
        [
            "git",
            "--no-pager",
            "--literal-pathspecs",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "--git-dir=" + str(root / ".git"),
            "--work-tree=" + str(root),
            "ls-files",
            "--error-unmatch",
            "--",
            name,
        ],
        root,
    )
    if observed.exit_code or observed.stdout != name.encode() + b"\n":
        raise Fault("policy_refusal", name)
    return _verified(artifact, read_bytes(root, name, artifact.size + 1))


def _download(artifact: Artifact, timeout: float) -> bytes:
    """Fetch one artifact from the registry host over verified HTTPS.

    Parameters
    ----------
    artifact : Artifact
        Pinned identity of the artifact; its origin is the admitted request path.
    timeout : float
        Seconds allowed for the connection and for each read.

    Returns
    -------
    bytes
        Complete bytes matching the pinned identity.

    Raises
    ------
    Fault
        ``input_unavailable`` (exit 3) for a connection, TLS, timeout or protocol failure and
        for any status other than 200, so a redirect is never followed;
        ``source_identity_mismatch`` for a declared length other than the pin, before the body
        is read, and for received bytes of another length or digest. The body read stops one
        byte after the pinned length.
    """
    connection = http.client.HTTPSConnection(
        REGISTRY_HOST, timeout=timeout, context=ssl.create_default_context()
    )
    try:
        connection.request("GET", artifact.origin, headers={"Accept-Encoding": "identity"})
        response = connection.getresponse()
        if response.status != 200:
            raise Fault("input_unavailable", artifact.filename, 3)
        if response.getheader("Content-Length") != str(artifact.size):
            raise Fault("source_identity_mismatch", artifact.filename)
        data = bytearray()
        while block := response.read(min(_CHUNK, artifact.size + 1 - len(data))):
            data.extend(block)
    except (OSError, http.client.HTTPException) as error:
        raise Fault("input_unavailable", artifact.filename, 3) from error
    finally:
        connection.close()
    return _verified(artifact, bytes(data))


def _publish(directory: Path, artifact: Artifact, data: bytes) -> None:
    """Write complete bytes durably, then link them exclusively under the final name.

    Parameters
    ----------
    directory : Path
        Destination directory created by this invocation.
    artifact : Artifact
        Identity whose name is published.
    data : bytes
        Verified complete bytes.

    Raises
    ------
    Fault
        ``output_failure`` for any write, durability or link failure. A partial temporary file
        is left for the caller, which removes the whole directory it created.
    """
    temporary = directory / (".spike-log-input-" + artifact.filename)
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, directory / artifact.filename, follow_symlinks=False)
        temporary.unlink()
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise Fault("output_failure", artifact.filename) from error


def _new_directory(destination: str) -> Path:
    """Create the destination exclusively beneath an existing unlinked parent.

    Parameters
    ----------
    destination : str
        Operator-selected directory that must not exist yet.

    Returns
    -------
    Path
        The created empty directory.

    Raises
    ------
    Fault
        A missing or linked parent, an existing destination (``output_exists``), or a
        creation failure (``output_failure``).
    """
    target = Path(os.path.abspath(destination))
    directory = root_directory(str(target.parent)) / target.name
    try:
        directory.mkdir(mode=0o755)
    except FileExistsError as error:
        raise Fault("output_exists", "artifacts") from error
    except OSError as error:
        raise Fault("output_failure", "artifacts") from error
    return directory


def acquire(root: Path, destination: str, timeout: float) -> None:
    """Acquire every selected artifact into a new flat directory, or leave nothing.

    All provenance, origin and tracked-file checks complete before the destination is
    created or any connection is made. Registry artifacts are then fetched one by one; each
    is verified before it is written. Any failure removes the directory this invocation
    created, with everything in it.

    Parameters
    ----------
    root : Path
        Validated repository root supplying the provenance and the tracked files.
    destination : str
        New directory to create, for example ``.tool-cache/environment-inputs``.
    timeout : float
        Seconds allowed for each registry connection and read.

    Raises
    ------
    Fault
        The first refusal; the destination then does not exist.
    """
    artifacts = selected(root)
    tracked = {
        artifact.filename: _tracked(root, artifact) for artifact in artifacts if artifact.tracked
    }
    directory = _new_directory(destination)
    try:
        for artifact in artifacts:
            data = tracked.get(artifact.filename)
            if data is None:
                data = _download(artifact, timeout)
            _publish(directory, artifact, data)
    except BaseException:
        shutil.rmtree(directory)
        raise
