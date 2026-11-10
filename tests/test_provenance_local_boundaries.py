# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — local source refusal boundaries

"""Exercise original local sources with independently selected adverse file inputs."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import stat
import sys
import zipfile
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from local_scaffold.limits import MAX_FILE, MAX_TREE
from local_scaffold.provenance_reproduction import package_record
from local_scaffold.provenance_wheels import product_files, wheel_members
from local_scaffold.reports import Fault
from tests.test_provenance_local import ARTIFACTS, MANIFEST, OWNER, reconstruct, reference
from tests.test_provenance_local import local_source as local_source


@pytest.mark.parametrize("change", ["name-type", "missing-name", "missing-response", "digest"])
def test_public_local_selection_refuses_invalid_or_missing_identity(
    local_source: tuple[dict[str, Json], dict[str, Json]], change: str
) -> None:
    """Invalid identity and absent source supply produce controlled public refusals."""
    expected, response = local_source
    name = cast(str, expected["name"])
    digest = cast(str, expected["source_input_sha256"])
    sources = {name: (digest, response)}
    if change == "name-type":
        expected["name"] = []
    elif change == "missing-name":
        del expected["name"]
    elif change == "missing-response":
        sources.clear()
    else:
        expected["source_input_sha256"] = "invalid"
        sources[name] = ("invalid", response)
    with pytest.raises(Fault) as raised:
        package_record(expected, sources, artifacts=ARTIFACTS, owner=OWNER)
    assert raised.value.exit_code == (3 if change == "missing-response" else 4)


@pytest.mark.parametrize(
    "change",
    [
        "manifest-shape",
        "files-shape",
        "row-shape",
        "row-extra",
        "path-type",
        "duplicate",
        "source-byte-count",
        "source-hash",
    ],
)
def test_selected_original_manifest_derivatives_refuse(
    local_source: tuple[dict[str, Json], dict[str, Json]], tmp_path: Path, change: str
) -> None:
    """Hash-bound adverse manifests cannot hide invalid rows or changed source bytes."""
    expected, response = local_source
    manifest: Json = json.loads(MANIFEST.read_bytes())
    rows = cast(list[Json], cast(dict[str, Json], manifest)["files"])
    first = cast(dict[str, Json], rows[0])
    if change == "manifest-shape":
        manifest = []
    elif change == "files-shape":
        cast(dict[str, Json], manifest)["files"] = {}
    elif change == "row-shape":
        rows[0] = "not a source descriptor"
    elif change == "row-extra":
        first["received_callback"] = "never executed"
    elif change == "path-type":
        first["path"] = 1
    elif change == "duplicate":
        rows[1] = rows[0]
    elif change == "source-byte-count":
        first["bytes"] = cast(int, first["bytes"]) + 1
    else:
        first["sha256"] = "0" * 64
    path = tmp_path / "source-manifest.json"
    path.write_text(json.dumps(manifest))
    selected = reference(path)
    response["owner_manifest"] = selected
    cast(dict[str, Json], expected["owner_source"])["manifest"] = {
        key: selected[key] for key in ("bytes", "sha256")
    }
    expected["source_input_sha256"] = hashlib.sha256(
        json.dumps(response, sort_keys=True).encode()
    ).hexdigest()
    with pytest.raises(Fault) as raised:
        reconstruct(expected, response)
    assert raised.value.exit_code == (2 if change in {"source-byte-count", "source-hash"} else 4)


@pytest.mark.parametrize(
    "change",
    [
        "reference-shape",
        "boolean-length",
        "wheel-shape",
        "wheel-name",
        "product-count",
        "product-prefix",
        "licences-shape",
        "licence-row",
        "licence-hash",
        "licence-population",
    ],
)
def test_local_descriptor_and_licence_boundaries(
    local_source: tuple[dict[str, Json], dict[str, Json]], change: str
) -> None:
    """Closed descriptors preserve exact types, product identity and full licence sets."""
    expected, response = local_source
    owner = cast(dict[str, Json], expected["owner_source"])
    if change == "reference-shape":
        cast(dict[str, Json], response["owner_manifest"])["extra"] = True
    elif change == "boolean-length":
        cast(dict[str, Json], response["owner_manifest"])["bytes"] = True
        cast(dict[str, Json], owner["manifest"])["bytes"] = True
    elif change == "wheel-shape":
        del cast(dict[str, Json], response["wheel"])["path"]
    elif change == "wheel-name":
        cast(dict[str, Json], expected["source_artifact"])["filename"] = "different.whl"
    elif change == "product-count":
        owner["product_file_count"] = cast(int, owner["product_file_count"]) + 1
    elif change == "product-prefix":
        owner["product_source_prefix"] = (
            None if expected["source_kind"] == "first_party_wheel" else "src/rfc8785"
        )
    elif change == "licences-shape":
        expected["license_files"] = {}
    elif change == "licence-row":
        cast(list[Json], expected["license_files"])[0] = {}
    elif change == "licence-hash":
        cast(dict[str, Json], cast(list[Json], expected["license_files"])[0])["sha256"] = "0" * 64
    else:
        cast(list[Json], expected["license_files"]).pop()
    expected["source_input_sha256"] = hashlib.sha256(
        json.dumps(response, sort_keys=True).encode()
    ).hexdigest()
    with pytest.raises(Fault) as raised:
        reconstruct(expected, response)
    assert raised.value.exit_code == (
        2 if change in {"wheel-name", "product-count", "licence-hash", "licence-population"} else 4
    )


@pytest.mark.parametrize("kind", ["root-link", "file-link", "fifo", "missing", "population"])
def test_real_product_tree_refuses_unsafe_or_unavailable_entries(tmp_path: Path, kind: str) -> None:
    """Actual links, special files and excessive populations refuse without traversal."""
    root = tmp_path / "product"
    root.mkdir()
    if kind == "root-link":
        link = tmp_path / "linked-product"
        link.symlink_to(root, target_is_directory=True)
        root = link
    elif kind == "file-link":
        (root / "linked").symlink_to(tmp_path)
    elif kind == "fifo":
        os.mkfifo(root / "fifo")
    elif kind == "missing":
        root.rmdir()
    else:
        for number in range(4097):
            (root / str(number)).touch()
    with pytest.raises(Fault) as raised:
        product_files(root)
    assert raised.value.exit_code == (3 if kind == "missing" else 2)


def test_real_product_tree_preserves_files_and_ignores_generated_cache(tmp_path: Path) -> None:
    """Only the generated cache directory is omitted from an actual nested namespace."""
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested/module.py").write_bytes(b"")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__/generated.pyc").write_bytes(b"generated")
    assert product_files(tmp_path) == {"nested/module.py"}


@pytest.mark.parametrize(
    "change",
    [
        "invalid-name",
        "version",
        "invalid-zip",
        "empty",
        "parent",
        "directory",
        "symlink",
        "metadata",
        "record",
        "wheel",
        "record-encoding",
        "record-csv",
        "record-width",
        "record-population",
        "record-self-hash",
        "installed-byte",
        "descriptor-hash",
        "licence-set",
    ],
)
def test_original_wheel_structure_and_installed_body_boundaries(
    local_source: tuple[dict[str, Json], dict[str, Json]], tmp_path: Path, change: str
) -> None:
    """Real ZIP and RECORD derivatives fail independently of their selected outer hashes."""
    expected, response = local_source
    original = ARTIFACTS / cast(str, cast(dict[str, Json], response["wheel"])["path"])
    distribution = importlib.metadata.distribution(cast(str, expected["name"]))
    filename = (
        "invalid.whl"
        if change == "invalid-name"
        else original.name.replace("-0.", "-9.", 1)
        if change == "version"
        else original.name
    )
    target = tmp_path / filename
    with zipfile.ZipFile(original) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    record_name = next(name for name in members if name.endswith(".dist-info/RECORD"))
    if change in {"metadata", "record", "wheel"}:
        suffix = {"metadata": "METADATA", "record": "RECORD", "wheel": "WHEEL"}[change]
        del members[record_name.removesuffix("RECORD") + suffix]
    elif change == "installed-byte":
        path = next(name for name in members if name.endswith("/__init__.py"))
        members[path] += b"\nchanged = True\n"
    if change in {"parent", "directory", "symlink"}:
        members[{"parent": "../escape", "directory": "directory/", "symlink": "linked"}[change]] = (
            b"untrusted"
        )
    if change == "licence-set":
        for row in cast(list[dict[str, Json]], expected["license_files"]):
            del members[cast(str, row["path"])]
    if record_name in members:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        for path, raw in members.items():
            digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
            writer.writerow(
                [path, "", ""] if path == record_name else [path, "sha256=" + digest, str(len(raw))]
            )
        members[record_name] = stream.getvalue().encode()
    if change.startswith("record-"):
        members[record_name] = {
            "record-encoding": b"\xff",
            "record-csv": b'"unterminated',
            "record-width": b"one-field\n",
            "record-population": b"",
            "record-self-hash": members[record_name].replace(
                (record_name + ",,").encode(), (record_name + ",sha256=unexpected,").encode()
            ),
        }[change]
    if change == "invalid-zip":
        target.write_bytes(b"not a ZIP file")
    else:
        with zipfile.ZipFile(target, "w") as output:
            if change != "empty":
                for path, raw in members.items():
                    entry = zipfile.ZipInfo(path)
                    if change == "symlink" and path == "linked":
                        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
                    output.writestr(entry, raw)
    descriptor: dict[str, Json] = {
        "filename": target.name,
        "bytes": target.stat().st_size,
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "kind": "bdist_wheel",
    }
    if change == "descriptor-hash":
        descriptor["sha256"] = "0" * 64
    with pytest.raises(Fault) as raised:
        if change == "licence-set":
            expected["source_artifact"] = descriptor
            response["wheel"] = reference(target)
            expected["source_input_sha256"] = hashlib.sha256(
                json.dumps(response, sort_keys=True).encode()
            ).hexdigest()
            reconstruct(expected, response)
        else:
            wheel_members(
                tmp_path,
                descriptor,
                distribution,
                namespace=cast(
                    str, cast(dict[str, Json], expected["owner_source"])["product_namespace"]
                ),
            )
    assert raised.value.exit_code == (4 if change == "invalid-name" else 2)


@pytest.mark.parametrize("local_source", ["evidence-manifest-toolkit"], indirect=True)
@pytest.mark.parametrize("change", ["missing-row", "source-body", "extra-source"])
def test_first_party_owner_tree_must_match_original_wheel(
    local_source: tuple[dict[str, Json], dict[str, Json]], tmp_path: Path, change: str
) -> None:
    """Genuine owner-source derivatives cannot drift from the installed original product."""
    expected, response = local_source
    manifest = json.loads(MANIFEST.read_bytes())
    source = cast(dict[str, Json], expected["owner_source"])
    prefix = cast(str, source["product_source_prefix"]) + "/"
    rows = cast(list[dict[str, Json]], manifest["files"])
    selected = next(row for row in rows if cast(str, row["path"]).startswith(prefix))
    owner = tmp_path / "owner"
    if change == "missing-row":
        rows.remove(selected)
        source["source_file_count"] = len(rows)
        owner = OWNER
    else:
        for row in rows:
            path = cast(str, row["path"])
            output = owner / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes((OWNER / path).read_bytes())
        if change == "source-body":
            output = owner / cast(str, selected["path"])
            output.write_bytes(output.read_bytes() + b"\nchanged = True\n")
            selected["bytes"] = output.stat().st_size
            selected["sha256"] = hashlib.sha256(output.read_bytes()).hexdigest()
        else:
            (owner / prefix / "unmanifested.py").write_bytes(b"unexpected = True\n")
    manifest_path = tmp_path / "source-manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    selected_manifest = reference(manifest_path)
    response["owner_manifest"] = selected_manifest
    source["manifest"] = {key: selected_manifest[key] for key in ("bytes", "sha256")}
    expected["source_input_sha256"] = hashlib.sha256(
        json.dumps(response, sort_keys=True).encode()
    ).hexdigest()
    with pytest.raises(Fault) as raised:
        reconstruct(expected, response, owner=owner)
    assert raised.value.code == "source_identity_mismatch" and raised.value.exit_code == 2


@pytest.mark.parametrize(
    "change",
    ["missing-metadata", "encoding", "version", "name", "extra-product", "changed-product"],
)
def test_native_distribution_files_are_checked_without_importing_package_code(
    local_source: tuple[dict[str, Json], dict[str, Json]], tmp_path: Path, change: str
) -> None:
    """Real native metadata and product-file derivatives refuse through the record API."""
    expected, response = local_source
    wheel = ARTIFACTS / cast(str, cast(dict[str, Json], response["wheel"])["path"])
    site = tmp_path / "native"
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        for path in names:
            output = site / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(archive.read(path))
    metadata = site / metadata_name
    if change == "missing-metadata":
        metadata.unlink()
    elif change == "encoding":
        metadata.write_bytes(b"\xff")
    elif change == "version":
        lines = metadata.read_text().splitlines(keepends=True)
        metadata.write_text(
            "".join("Version: 99.0\n" if line.startswith("Version: ") else line for line in lines)
        )
    elif change == "name":
        metadata.write_text(
            "".join(
                line
                for line in metadata.read_text().splitlines(keepends=True)
                if not line.startswith("Name: ")
            )
        )
    else:
        namespace = cast(str, cast(dict[str, Json], expected["owner_source"])["product_namespace"])
        product_path = (
            site / namespace / ("extra.py" if change == "extra-product" else "__init__.py")
        )
        product_path.write_bytes(b"changed = True\n")
    sys.path.insert(0, str(site))
    try:
        with pytest.raises(Fault) as raised:
            reconstruct(expected, response)
    finally:
        assert sys.path.pop(0) == str(site)
    assert raised.value.exit_code == 2


def test_inaccessible_native_namespace_is_unavailable(tmp_path: Path) -> None:
    """An actual inaccessible child directory fails without silently omitting its files."""
    child = tmp_path / "inaccessible"
    child.mkdir()
    (child / "retained.py").write_bytes(b"original = True\n")
    child.chmod(0)
    try:
        with pytest.raises(Fault) as raised:
            product_files(tmp_path)
    finally:
        child.chmod(0o700)
    assert raised.value.exit_code == 3


@pytest.mark.parametrize("local_source", ["evidence-manifest-toolkit"], indirect=True)
def test_actual_owner_source_aggregate_budget_refuses(
    local_source: tuple[dict[str, Json], dict[str, Json]], tmp_path: Path
) -> None:
    """A real hash-bound source population cannot exceed the cumulative byte budget."""
    expected, response = local_source
    owner = tmp_path / "owner"
    owner.mkdir()
    body = owner / "source-0"
    block = b"\x00" * 65536
    with body.open("wb") as stream:
        for _ in range(MAX_FILE // len(block)):
            stream.write(block)
    digest = hashlib.sha256(body.read_bytes()).hexdigest()
    rows: list[Json] = [{"path": body.name, "bytes": MAX_FILE, "sha256": digest}]
    for number in range(1, MAX_TREE // MAX_FILE + 1):
        path = owner / ("source-" + str(number))
        os.link(body, path)
        rows.append({"path": path.name, "bytes": MAX_FILE, "sha256": digest})
    manifest = tmp_path / "oversized-source.json"
    manifest.write_text(json.dumps({"files": rows}))
    selected = reference(manifest)
    response["owner_manifest"] = selected
    source = cast(dict[str, Json], expected["owner_source"])
    source["source_file_count"] = len(rows)
    source["manifest"] = {key: selected[key] for key in ("bytes", "sha256")}
    expected["source_input_sha256"] = hashlib.sha256(
        json.dumps(response, sort_keys=True).encode()
    ).hexdigest()
    with pytest.raises(Fault) as raised:
        reconstruct(expected, response, owner=owner)
    assert raised.value.code == "resource_limit" and raised.value.exit_code == 2


@pytest.mark.parametrize("namespace", ["", "../outside"])
def test_wheel_namespace_requires_an_independent_safe_package_name(
    local_source: tuple[dict[str, Json], dict[str, Json]], namespace: str
) -> None:
    """The selected namespace is one package directory, never a path traversal."""
    expected, response = local_source
    artifact = cast(dict[str, Json], expected["source_artifact"])
    original = ARTIFACTS / cast(str, cast(dict[str, Json], response["wheel"])["path"])
    native = importlib.metadata.distribution(cast(str, expected["name"]))
    with pytest.raises(Fault) as raised:
        wheel_members(original.parent, artifact, native, namespace=namespace)
    assert raised.value.code == "configuration_invalid" and raised.value.exit_code == 4


def test_empty_structural_wheel_directories_preserve_record_file_identity(
    local_source: tuple[dict[str, Json], dict[str, Json]], tmp_path: Path
) -> None:
    """Real empty ZIP directories are inert while all recorded file bytes stay checked."""
    expected, response = local_source
    original = ARTIFACTS / cast(str, cast(dict[str, Json], response["wheel"])["path"])
    target = tmp_path / original.name
    with zipfile.ZipFile(original) as archive, zipfile.ZipFile(target, "w") as output:
        for entry in archive.infolist():
            output.writestr(entry, archive.read(entry))
        output.writestr("structural-only/", b"")
    wheel_ref = reference(target)
    response["wheel"] = wheel_ref
    artifact = cast(dict[str, Json], expected["source_artifact"])
    artifact["bytes"] = wheel_ref["bytes"]
    artifact["sha256"] = wheel_ref["sha256"]
    expected["source_input_sha256"] = hashlib.sha256(
        json.dumps(response, sort_keys=True).encode()
    ).hexdigest()
    assert reconstruct(expected, response) == expected
