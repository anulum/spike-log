# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — hash-bound first-party and maintained dependency sources

"""Reconstruct local package evidence without inventing publisher metadata."""

from __future__ import annotations

import hashlib
import importlib.metadata
import re
from pathlib import Path
from typing import cast

from .committed_source import verify_committed_source
from .inputs import Json, parse_json, read_bytes, relative_path
from .limits import MAX_ENTRIES, MAX_FILE, MAX_TREE
from .provenance_wheels import product_files, wheel_members
from .reports import Fault

LOCAL_KINDS = frozenset({"first_party_wheel", "maintained_wheel"})
_RECORD_FIELDS = frozenset(
    {
        "name",
        "version",
        "role",
        "source_kind",
        "source_artifact",
        "owner_source",
        "source_input_sha256",
        "metadata_sha256",
        "metadata_version",
        "requires_python",
        "requires_dist",
        "license_expression",
        "license_label",
        "license_classifiers",
        "license_files",
    }
)


def _reference(directory: Path, reference: Json, expected: Json) -> bytes:
    """Read bounded original bytes against an independently selected length/hash."""
    if (
        not isinstance(reference, dict)
        or set(reference) != {"path", "bytes", "sha256"}
        or not isinstance(reference["path"], str)
        or not isinstance(expected, dict)
        or set(expected) != {"bytes", "sha256"}
        or {key: reference[key] for key in ("bytes", "sha256")} != expected
        or type(reference["bytes"]) is not int
        or type(expected["bytes"]) is not int
        or not 0 <= expected["bytes"] <= MAX_FILE
        or not isinstance(expected["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]) is None
    ):
        raise Fault("configuration_invalid", "local-source-reference", 4)
    data = read_bytes(directory, reference["path"], MAX_FILE)
    if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
        raise Fault("source_identity_mismatch", reference["path"])
    return data


def package_record(
    original: dict[str, Json],
    digest: str,
    response: dict[str, Json],
    *,
    artifacts: Path,
    owner: Path,
) -> dict[str, Json]:
    """Reconstruct a local record from its complete original wheel/source evidence.

    Parameters
    ----------
    original : dict[str, Json]
        Independently selected closed first-party or maintained package baseline.
        Its source hashes are expectations, never learned from received responses.
    digest : str
        SHA-256 of the original local-source response bytes.
    response : dict[str, Json]
        Closed input descriptors for the wheel, owner manifest and build evidence.
    artifacts : Path
        Independently selected input root; descriptor paths never select code.
    owner : Path
        Independently selected owning source tree, read only.

    Returns
    -------
    dict[str, Json]
        Actual installed metadata and licences plus unchanged selected owner/build
        identities. This establishes source correspondence, not build execution,
        security admission or authority for owner work in progress. A committed-state
        record additionally proves its complete pinned manifest against the actual
        clean native owner commit and tree; historical WIP records retain their meaning.

    Raises
    ------
    Fault
        Raised for missing, malformed or mismatching original source evidence.
    """
    if (
        set(original) != _RECORD_FIELDS
        or original["role"] not in ("direct", "transitive")
        or not isinstance(original["source_kind"], str)
        or original["source_kind"] not in LOCAL_KINDS
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or digest != original["source_input_sha256"]
        or set(response) != {"source_kind", "wheel", "owner_manifest", "build_inputs"}
        or response["source_kind"] != original["source_kind"]
        or not isinstance(original["name"], str)
        or not isinstance(original["version"], str)
        or not isinstance(original["owner_source"], dict)
    ):
        raise Fault("configuration_invalid", "local-source", 4)
    name = original["name"]
    source = original["owner_source"]
    if (
        set(source)
        != {
            "repository",
            "state",
            "manifest",
            "source_file_count",
            "product_source_prefix",
            "product_namespace",
            "product_file_count",
            "build_inputs",
        }
        or not isinstance(source["repository"], str)
        or not source["repository"]
        or source["state"] not in ("owner_work_in_progress", "committed")
        or type(source["source_file_count"]) is not int
        or not 0 < source["source_file_count"] <= MAX_ENTRIES
        or not isinstance(source["product_namespace"], str)
        or re.fullmatch(r"[a-z][a-z0-9_]*", source["product_namespace"]) is None
        or type(source["product_file_count"]) is not int
        or not 0 < source["product_file_count"] <= MAX_ENTRIES
        or not isinstance(source["build_inputs"], list)
        or not source["build_inputs"]
        or not isinstance(response["build_inputs"], list)
        or len(response["build_inputs"]) != len(source["build_inputs"])
    ):
        raise Fault("configuration_invalid", name, 4)
    manifest_bytes = _reference(artifacts, response["owner_manifest"], source["manifest"])
    manifest = parse_json(manifest_bytes, name)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise Fault("configuration_invalid", name, 4)
    files = cast(list[Json], manifest["files"])
    if len(files) != source["source_file_count"]:
        raise Fault("source_identity_mismatch", name)
    source_files: dict[str, bytes] = {}
    total = 0
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise Fault("configuration_invalid", name, 4)
        path = row["path"]
        if not isinstance(path, str) or path in source_files:
            raise Fault("configuration_invalid", name, 4)
        data = _reference(owner, row, {key: row[key] for key in ("bytes", "sha256")})
        total += len(data)
        if total > MAX_TREE:
            raise Fault("resource_limit", name)
        source_files[path] = data
    if source["state"] == "committed":
        verify_committed_source(owner, manifest, source_files)
    for reference, expected in zip(response["build_inputs"], source["build_inputs"], strict=True):
        _reference(artifacts, reference, expected)
    wheel = response["wheel"]
    artifact = original["source_artifact"]
    if (
        not isinstance(wheel, dict)
        or set(wheel) != {"path", "bytes", "sha256"}
        or not isinstance(wheel["path"], str)
        or not isinstance(artifact, dict)
    ):
        raise Fault("configuration_invalid", name, 4)
    _reference(artifacts, wheel, {key: artifact.get(key) for key in ("bytes", "sha256")})
    wheel_path = relative_path(artifacts, wheel["path"])
    if wheel_path.name != artifact.get("filename"):
        raise Fault("source_identity_mismatch", name)
    try:
        distribution = importlib.metadata.distribution(name)
        metadata = distribution.read_text("METADATA")
    except importlib.metadata.PackageNotFoundError as error:
        raise Fault("dependency_alignment.wrong-producer", name) from error
    except UnicodeError as error:
        raise Fault("source_identity_mismatch", name) from error
    if metadata is None:
        raise Fault("dependency_alignment.wrong-producer", name)
    if distribution.version != original["version"]:
        raise Fault("source_identity_mismatch", name)
    members = wheel_members(
        wheel_path.parent, artifact, distribution, namespace=source["product_namespace"]
    )
    namespace = source["product_namespace"] + "/"
    product = {path: data for path, data in members.items() if path.startswith(namespace)}
    if len(product) != source["product_file_count"]:
        raise Fault("source_identity_mismatch", name)
    prefix = source["product_source_prefix"]
    if original["source_kind"] == "first_party_wheel":
        if not isinstance(prefix, str):
            raise Fault("configuration_invalid", name, 4)
        selected = {path for path in source_files if path.startswith(prefix + "/")}
        expected_paths = {prefix + "/" + path.removeprefix(namespace) for path in product}
        if selected != expected_paths:
            raise Fault("source_identity_mismatch", name)
        if product_files(relative_path(owner, prefix)) != {
            path.removeprefix(namespace) for path in product
        }:
            raise Fault("source_identity_mismatch", name)
        for path, data in product.items():
            if source_files[prefix + "/" + path.removeprefix(namespace)] != data:
                raise Fault("source_identity_mismatch", path)
    elif prefix is not None:
        raise Fault("configuration_invalid", name, 4)
    licences = original["license_files"]
    if not isinstance(licences, list):
        raise Fault("configuration_invalid", name, 4)
    declared = distribution.metadata.get_all("License-File") or []
    metadata_name = next(path for path in members if path.endswith(".dist-info/METADATA"))
    metadata_prefix = metadata_name.removesuffix("METADATA")
    if declared:
        expected_licences = {metadata_prefix + "licenses/" + path for path in declared}
    elif original["source_kind"] == "maintained_wheel" and original["metadata_version"] == "2.1":
        expected_licences = {
            path
            for path in members
            if path.startswith(metadata_prefix) and path.rsplit("/", 1)[-1] in {"LICENSE", "NOTICE"}
        }
        if not expected_licences:
            raise Fault("source_identity_mismatch", name)
    else:
        raise Fault("source_identity_mismatch", name)
    if not expected_licences <= members.keys():
        raise Fault("source_identity_mismatch", name)
    actual_licences: list[Json] = []
    for row in licences:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "bytes", "sha256"}
            or not isinstance(row["path"], str)
            or row["path"] not in expected_licences
        ):
            raise Fault("configuration_invalid", name, 4)
        data = members[row["path"]]
        expected = {
            "path": row["path"],
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        if row != expected:
            raise Fault("source_identity_mismatch", row["path"])
        actual_licences.append(expected)
    if (
        len(actual_licences) != len(expected_licences)
        or {cast(dict[str, Json], row)["path"] for row in actual_licences} != expected_licences
    ):
        raise Fault("source_identity_mismatch", name)
    result = original.copy()
    result.update(
        metadata_sha256=hashlib.sha256(metadata.encode()).hexdigest(),
        metadata_version=distribution.metadata.get("Metadata-Version"),
        requires_python=distribution.metadata.get("Requires-Python"),
        requires_dist=cast(list[Json], distribution.requires or []),
        license_expression=distribution.metadata.get("License-Expression"),
        license_label=distribution.metadata.get("License"),
        license_classifiers=[
            value
            for value in distribution.metadata.get_all("Classifier") or []
            if value.startswith("License ::")
        ],
        license_files=actual_licences,
    )
    for key in (
        "metadata_sha256",
        "metadata_version",
        "requires_python",
        "requires_dist",
        "license_expression",
        "license_label",
        "license_classifiers",
        "license_files",
    ):
        if result[key] != original[key]:
            raise Fault("source_identity_mismatch", name)
    return result
