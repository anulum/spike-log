# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Bind current audit admission to trusted code and the actual installed graph."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import sys
from email.parser import HeaderParser
from pathlib import Path
from typing import Final, cast

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from .inputs import Json, json_object, read_bytes
from .policy import EXPECTED_GRAPH, PROVENANCE_SHA256, PYTHON_SUPPORTED_RANGE
from .reports import Fault

VULNERABILITY_SERVICE: Final = "osv"
VULNERABILITY_ENDPOINT: Final = "https://api.osv.dev/v1/query"
ADVISORY_SOURCE: Final[dict[str, Json]] = {
    "service": VULNERABILITY_SERVICE,
    "url": VULNERABILITY_ENDPOINT,
    "database_revision": None,
}

REGISTRY_GRAPH: Final = {
    name: version
    for name, version in EXPECTED_GRAPH.items()
    if name not in ("rfc8785", "evidence-manifest-toolkit")
}

POLICY_INPUTS = (
    ".make/environment.mk",
    ".make/fixtures.mk",
    ".make/quality.mk",
    "Makefile",
    "pyproject.toml",
    "requirements-dev.in",
    "requirements-dev.txt",
    "dependency-provenance.json",
    ".pre-commit-config.yaml",
    ".github/workflows/security-audit.yml",
    ".github/workflows/pre-commit.yml",
)


def trusted_root() -> Path:
    """Locate the executing trusted installation, independent of inspected input.

    Returns
    -------
    Path
        Resolved installation owning this implementation's tools directory.
    """
    return Path(__file__).resolve().parents[2]


def encode(value: Json) -> bytes:
    """Serialize a finite trusted record into deterministic UTF-8 bytes.

    Parameters
    ----------
    value : Json
        Closed authored record whose values have already passed semantic validation.

    Returns
    -------
    bytes
        Sorted compact ASCII-safe JSON with one terminal newline.
    """
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def policy_digest(root: Path) -> str:
    """Bind the entire trusted Python tooling tree and fixed policy inputs.

    Parameters
    ----------
    root : Path
        Actual executing trusted installation, never a received manifest root.

    Returns
    -------
    str
        Domain-separated deterministic path-and-original-byte digest.

    Raises
    ------
    Fault
        Raised for unbounded, changed, unsafe or unavailable trusted source inputs.
    """
    paths: list[Path] = []
    for path in (root / "tools").rglob("*.py"):
        if len(paths) == 512:
            raise Fault("resource_limit")
        paths.append(path)
    if not paths:
        raise Fault("resource_limit")
    names = sorted(str(p.relative_to(root)) for p in paths) + list(POLICY_INPUTS)
    entries: dict[str, Json] = {}
    for name in names:
        data = read_bytes(root, name)
        entries[name] = {"sha256": hashlib.sha256(data).hexdigest(), "byte_length": len(data)}
    return hashlib.sha256(b"spike_log.audit-source-policy.v1\0" + encode(entries)).hexdigest()


def context() -> dict[str, Json]:
    """Measure actual source, installation, interpreter and complete installed metadata.

    Read each producer identity and digest from one complete original METADATA body.

    Returns
    -------
    dict of str to Json
        Independently computed closed fields required by each local producer receipt.

    Raises
    ------
    Fault
        Raised for an unsupported interpreter, altered provenance or incomplete/duplicate/changed installed producers.
    """
    root = trusted_root()
    if platform.python_version() not in SpecifierSet(PYTHON_SUPPORTED_RANGE):
        raise Fault("dependency_alignment.incompatible-patch", "dependency-provenance.json")
    if (
        hashlib.sha256(read_bytes(root, "dependency-provenance.json")).hexdigest()
        != PROVENANCE_SHA256
    ):
        raise Fault("source_identity_mismatch", "dependency-provenance.json")
    value = json_object(root, "dependency-provenance.json")
    # The exact admitted source digest above binds this authored package-record shape.
    packages = cast(list[dict[str, Json]], value["packages"])
    expected: dict[str, Json] = {
        canonicalize_name(cast(str, item["name"])): item["metadata_sha256"] for item in packages
    }
    actual: dict[str, Json] = {}
    versions: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        metadata = distribution.read_text("METADATA")
        if metadata is None:
            raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json")
        headers = HeaderParser().parsestr(metadata.partition("\n\n")[0], headersonly=True)
        name, version = headers.get("Name"), headers.get("Version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json")
        key = canonicalize_name(name)
        if key in actual:
            raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json")
        actual[key] = hashlib.sha256(metadata.encode()).hexdigest()
        versions[key] = version
    if versions != EXPECTED_GRAPH or actual != expected:
        raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json")
    registry_identity: dict[str, Json] = dict(REGISTRY_GRAPH)
    executable = Path(sys.executable).resolve()
    return {
        "registry_graph_sha256": hashlib.sha256(encode(registry_identity)).hexdigest(),
        "trusted_policy_sha256": policy_digest(root),
        "installed_metadata_sha256": hashlib.sha256(encode(actual)).hexdigest(),
        "python_version": platform.python_version(),
        "python_executable_sha256": hashlib.sha256(
            read_bytes(executable.parent, executable.name, 100_000_000)
        ).hexdigest(),
        "installation_sha256": hashlib.sha256(
            b"spike_log.trusted-installation.v1\0" + str(root).encode()
        ).hexdigest(),
    }
