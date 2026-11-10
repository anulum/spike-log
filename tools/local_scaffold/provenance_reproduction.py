# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Reconstruct prospective dependency provenance from actual offline sources."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import cast

from packaging.utils import canonicalize_name

from .inputs import Json, json_object, parse_json, read_bytes
from .inventory import publish
from .metadata import check
from .policy import PROVENANCE_SHA256
from .provenance_sources import SourceResponses, check_direct_requirements, load
from .reports import Fault, Report


def package_record(
    original: dict[str, Json],
    sources: SourceResponses,
    *,
    artifacts: Path | None = None,
    owner: Path | None = None,
) -> dict[str, Json]:
    """Rebuild one record from installed bytes and its selected source evidence.

    Parameters
    ----------
    original : dict[str, Json]
        Hash-bound baseline package record supplying explicit licence-path and artifact selections.
    sources : SourceResponses
        Verified source responses indexed by canonical package name. The selected
        package must be present; a capture may supply only that record.
    artifacts : Path | None
        Independently chosen local artifact root; required for local wheel records.
    owner : Path | None
        Independently chosen owning source tree; required for local wheel records.

    Returns
    -------
    dict[str, Json]
        Reconstructed fields with native METADATA text identity, original ordering,
        and complete raw response and declared licence-file byte hashes.

    Raises
    ------
    Fault
        Raised for missing installed metadata, a different native distribution version,
        or a changed selected registry artifact identity.
    """
    if "source_kind" in original:
        from .provenance_local import LOCAL_KINDS
        from .provenance_local import package_record as local_record

        kind = original["source_kind"]
        if not isinstance(kind, str) or kind not in LOCAL_KINDS:
            raise Fault("configuration_invalid", "local-source", 4)
        if artifacts is None or owner is None:
            raise Fault("input_unavailable", "local-source", 3)
        name = original.get("name")
        if not isinstance(name, str):
            raise Fault("configuration_invalid", "local-source", 4)
        if name not in sources:
            raise Fault("input_unavailable", "local-source", 3)
        digest, response = sources[name]
        return local_record(original, digest, response, artifacts=artifacts, owner=owner)
    name = cast(str, original["name"])
    version = cast(str, original["version"])
    digest, response = sources[name]
    info, urls = response.get("info"), response.get("urls")
    if (
        not isinstance(info, dict)
        or not isinstance(info.get("name"), str)
        or canonicalize_name(cast(str, info["name"])) != name
        or info.get("version") != version
        or not isinstance(urls, list)
    ):
        raise Fault("source_identity_mismatch", name)
    artifact = cast(dict[str, Json], original["source_artifact"])
    matches = [
        entry
        for entry in urls
        if isinstance(entry, dict) and entry.get("filename") == artifact["filename"]
    ]
    if len(matches) != 1:
        raise Fault("source_identity_mismatch", name)
    selected = matches[0]
    hashes = selected.get("digests")
    if not isinstance(hashes, dict):
        raise Fault("configuration_invalid", name, 4)
    reconstructed_artifact: dict[str, Json] = {
        "bytes": selected.get("size"),
        "filename": selected.get("filename"),
        "kind": selected.get("packagetype"),
        "sha256": hashes.get("sha256"),
        "url": selected.get("url"),
    }
    if reconstructed_artifact != artifact:
        raise Fault("source_identity_mismatch", name)
    distribution = importlib.metadata.distribution(name)
    metadata = distribution.read_text("METADATA")
    if metadata is None:
        raise Fault("dependency_alignment.wrong-producer", name)
    if distribution.version != version:
        raise Fault("source_identity_mismatch", name)
    site = Path(str(distribution.locate_file("")))
    licences: list[Json] = []
    for declared in cast(list[dict[str, Json]], original["license_files"]):
        path = cast(str, declared["path"])
        data = read_bytes(site, path)
        licences.append(
            {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
    result = original.copy()
    result.update(
        metadata_sha256=hashlib.sha256(metadata.encode()).hexdigest(),
        official_metadata_sha256=digest,
        requires_dist=cast(list[Json], distribution.requires or []),
        license_expression=distribution.metadata.get("License-Expression"),
        license_label=distribution.metadata.get("License"),
        license_classifiers=[
            value
            for value in cast(list[str], distribution.metadata.get_all("Classifier") or [])
            if value.startswith("License ::")
        ],
        license_files=licences,
        source_artifact=reconstructed_artifact,
    )
    return result


def reproduce(
    root: Path,
    inputs: Path,
    report: Report,
    *,
    output: str | None = None,
    reference: str = "dependency-provenance.json",
    artifacts: Path | None = None,
    owner: Path | None = None,
) -> None:
    """Generate a separate candidate or compare the complete reconstructed manifest.

    Parameters
    ----------
    root : Path
        Repository supplying current independently checked metadata and the fixed provenance baseline.
    inputs : Path
        Explicit complete offline snapshot; no network or audit producer is invoked.
    report : Report
        Receives baseline, repository or complete generated-manifest drift findings.
    output : str | None
        New root-contained candidate destination; None selects read-only comparison.
    reference : str
        Root-relative comparison manifest, defaulting to the current repository baseline.

    artifacts : Path | None
        Explicit local artifact root, defaulting to the independently selected input root.
    owner : Path | None
        Explicit source owner root; missing local sources refuse rather than querying a registry.

    Raises
    ------
    Fault
        Raised for unavailable inputs, changed source identities or failed candidate publication.
    """
    check(root, report)
    if report.exit_code:
        return
    original_bytes = read_bytes(root, "dependency-provenance.json")
    if hashlib.sha256(original_bytes).hexdigest() != PROVENANCE_SHA256:
        raise Fault("source_identity_mismatch", "dependency-provenance.json")
    original = cast(dict[str, Json], parse_json(original_bytes, "dependency-provenance.json"))
    check_direct_requirements(root)
    sources = load(inputs)
    packages = cast(list[dict[str, Json]], original["packages"])
    result = original.copy()
    result["packages"] = [
        package_record(record, sources, artifacts=artifacts or inputs, owner=owner)
        for record in packages
    ]
    if output is None:
        if json_object(root, reference) != result:
            report.add("source_identity_mismatch", reference)
    else:
        data = (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
        publish(root, output, data)
