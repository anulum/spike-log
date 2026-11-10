# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Anchor private audit objects and kernel leases to one trusted installation."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import re
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .inputs import require_byte_budget
from .policy import MAX_INPUT
from .reports import Fault

LOCATION = ".tool-cache/security-admissions"
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _directory(parent: int, name: str, create: bool) -> int:
    """Open one anchored directory without following a substituted link."""
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            pass
    return os.open(name, DIRECTORY, dir_fd=parent)


@dataclass(frozen=True, slots=True)
class AdmissionStore:
    """Open trusted directory descriptors held for the entire native lease.

    Attributes
    ----------
    root : int
        Anchored installation directory descriptor.
    cache : int
        Anchored private tool-cache directory descriptor.
    directory : int
        Anchored security-admissions directory descriptor.
    objects : int
        Anchored immutable-object directory descriptor.
    """

    root: int
    cache: int
    directory: int
    objects: int

    def read(self, name: str, *, object_file: bool = False) -> bytes:
        """Read an immutable digest object or fixed HEAD under the current lease.

        Parameters
        ----------
        name : str
            HEAD.json or an exact lowercase SHA-256, never a received path.
        object_file : bool
            Select the immutable object directory rather than HEAD.

        Returns
        -------
        bytes
            Complete bounded original bytes with verified regular kind and digest.

        Raises
        ------
        Fault
            Raised for invalid selector, unsafe kind, changed bytes or digest mismatch.
        OSError
            Raised for actual native read/descriptor errors; the store context maps them safely.
        """
        if (object_file and re.fullmatch(r"[a-f0-9]{64}", name) is None) or (
            not object_file and name != "HEAD.json"
        ):
            raise Fault("configuration_invalid", LOCATION, 4)
        parent = self.objects if object_file else self.directory
        filename = name + ".json" if object_file else name
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise Fault("repository_inventory.special-file", LOCATION)
            require_byte_budget(before.st_size, MAX_INPUT, LOCATION)
            data = bytearray()
            while len(data) <= MAX_INPUT:
                block = os.read(descriptor, min(65536, MAX_INPUT + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            require_byte_budget(len(data), MAX_INPUT, LOCATION)
            after = os.fstat(descriptor)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or len(data) != before.st_size:
                raise Fault("source_identity_mismatch", LOCATION)
            if object_file and hashlib.sha256(data).hexdigest() != name:
                raise Fault("source_identity_mismatch", LOCATION)
            return bytes(data)
        finally:
            os.close(descriptor)

    def _temporary(self, parent: int, data: bytes) -> str:
        """Durably write complete owned bytes; retain a failed temporary as evidence."""
        require_byte_budget(len(data), MAX_INPUT, LOCATION)
        name = ".audit-" + uuid.uuid4().hex
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(descriptor, remaining)
                if written == 0:
                    raise Fault("output_failure", LOCATION)
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return name

    def object(self, data: bytes) -> str:
        """Install an immutable object exclusively and verify any existing object.

        Parameters
        ----------
        data : bytes
            Original bounded audit, capture or closed receipt bytes.

        Returns
        -------
        str
            SHA-256 selecting the complete immutable object.

        Raises
        ------
        Fault
            Raised if an existing object is unsafe or differs from the exact bytes.
        OSError
            Raised for native publication or durability failure.
        """
        digest = hashlib.sha256(data).hexdigest()
        temporary = self._temporary(self.objects, data)
        try:
            os.link(
                temporary,
                digest + ".json",
                src_dir_fd=self.objects,
                dst_dir_fd=self.objects,
                follow_symlinks=False,
            )
        except FileExistsError:
            pass
        self.read(digest, object_file=True)
        os.unlink(temporary, dir_fd=self.objects)
        os.fsync(self.objects)
        return digest

    def _replace(self, parent: int, name: str, data: bytes) -> None:
        """Replace only an absent or regular authored destination, never a link."""
        try:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if before is not None and not stat.S_ISREG(before.st_mode):
            raise Fault("policy_refusal", LOCATION)
        temporary = self._temporary(parent, data)
        try:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current != before:
            raise Fault("source_identity_mismatch", LOCATION)
        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)

    def publish_head(self, data: bytes) -> None:
        """Durably replace the fixed HEAD after all required object publications.

        Parameters
        ----------
        data : bytes
            Closed pending or terminal HEAD produced by trusted code.

        Raises
        ------
        Fault
            Raised for unsafe destination or changed identity.
        OSError
            Raised for native publication or fsync failure.
        """
        self._replace(self.directory, "HEAD.json", data)

    def publish_audit(self, data: bytes) -> None:
        """Publish retained producer output at the fixed received-audit location.

        Parameters
        ----------
        data : bytes
            Original native JSON audit bytes already retained as an immutable object.

        Raises
        ------
        Fault
            Raised for unsafe or changed output kind/identity.
        OSError
            Raised for native output publication or durability failure.
        """
        directory = _directory(self.cache, "security", True)
        try:
            self._replace(directory, "pip-audit.json", data)
        finally:
            os.close(directory)


@contextmanager
def open_store(root: Path, *, write: bool = False) -> Iterator[AdmissionStore]:
    """Hold anchored directory handles and one nonblocking shared/exclusive lease.

    Parameters
    ----------
    root : Path
        Absolute trusted installation root, never an inspected repository selector.
    write : bool
        Explicit producer admission may create directories; default consumer never writes.

    Yields
    ------
    AdmissionStore
        Anchored descriptors held until all reading/publication has completed.

    Raises
    ------
    Fault
        Raised for unsafe/missing native resources, contention or publication failure.
    """
    descriptors: list[int] = []
    try:
        descriptors.append(os.open("/", DIRECTORY))
        for part in root.parts[1:]:
            descriptors.append(_directory(descriptors[-1], part, False))
        installed = descriptors[-1]
        descriptors.append(_directory(installed, ".tool-cache", write))
        cache = descriptors[-1]
        descriptors.append(_directory(cache, "security-admissions", write))
        directory = descriptors[-1]
        descriptors.append(_directory(directory, "objects", write))
        objects = descriptors[-1]
        flags = os.O_RDWR | os.O_CREAT if write else os.O_RDONLY
        descriptors.append(
            os.open(
                "admission.lock", flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory
            )
        )
        if not stat.S_ISREG(os.fstat(descriptors[-1]).st_mode):
            raise Fault("policy_refusal", LOCATION)
        fcntl.flock(descriptors[-1], (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        if write:
            os.fsync(directory)
            os.fsync(cache)
            os.fsync(installed)
        yield AdmissionStore(installed, cache, directory, objects)
    except BlockingIOError as error:
        raise Fault("tool_unavailable", LOCATION, 3) from error
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Fault("policy_refusal", LOCATION) from error
        if write:
            raise Fault("output_failure", LOCATION) from error
        raise Fault("input_unavailable", LOCATION, 3) from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
