# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — actual local dependency source reconstruction

"""Exercise the public record API against genuine Common and maintained RFC artifacts."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from local_scaffold.provenance_reproduction import package_record
from local_scaffold.reports import Fault
from tests.conftest import SOURCE

ARTIFACTS = Path(os.environ.get("SPIKE_LOG_TEST_ARTIFACTS", str(SOURCE))).absolute()
INPUTS = Path(
    os.environ.get("SPIKE_LOG_TEST_LOCAL_INPUTS", str(SOURCE / ".tool-cache/environment-inputs"))
).absolute()
OWNER = Path(os.environ.get("SPIKE_LOG_TEST_OWNER_SOURCE", str(INPUTS / "owner"))).absolute()
MANIFEST = INPUTS / "owner-source-inputs.json"


def reference(path: Path) -> dict[str, Json]:
    """Bind actual original source bytes without copying the artifact."""
    raw = path.read_bytes()
    return {
        "path": path.relative_to(ARTIFACTS).as_posix(),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


@pytest.fixture(params=["evidence-manifest-toolkit", "rfc8785"])
def local_source(request: pytest.FixtureRequest) -> tuple[dict[str, Json], dict[str, Json]]:
    """Select real installed distributions and their retained original source inputs."""
    name = str(request.param)
    distribution = importlib.metadata.distribution(name)
    common = name == "evidence-manifest-toolkit"
    wheel = (
        INPUTS / "evidence_manifest_toolkit-0.0.0.dev0-py3-none-any.whl"
        if common
        else INPUTS / "rfc8785-0.1.4+emt.1-py3-none-any.whl"
    )
    expected_hash = (
        "b4ade75b41bcdf0126e5ea1fb2ce96fddc5a99ab738a822ddc0e7fbf119ccb72"
        if common
        else "e04761706fcbbb5f0afd5fa74a7e6ea7484ce97f073adb5372ab8ee93230c48e"
    )
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == expected_hash
    build_inputs = (
        [
            INPUTS / "common-build-producer.json",
            INPUTS / "common-wheel-source-identity.json",
            INPUTS / "common-sdist-rebuild-identity.json",
        ]
        if common
        else [INPUTS / "rfc8785-source-provenance.json"]
    )
    kind = "first_party_wheel" if common else "maintained_wheel"
    response: dict[str, Json] = {
        "source_kind": kind,
        "wheel": reference(wheel),
        "owner_manifest": reference(MANIFEST),
        "build_inputs": [reference(path) for path in build_inputs],
    }
    manifest = json.loads(MANIFEST.read_bytes())
    namespace = "evidence_manifest_toolkit" if common else "rfc8785"
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        prefix = next(n for n in names if n.endswith(".dist-info/METADATA")).removesuffix(
            "METADATA"
        )
        licence_names = (
            [
                prefix + "licenses/" + path
                for path in distribution.metadata.get_all("License-File") or []
            ]
            if common
            else [prefix + "LICENSE", prefix + "NOTICE"]
        )
        licences: list[Json] = [
            {
                "path": path,
                "bytes": len(archive.read(path)),
                "sha256": hashlib.sha256(archive.read(path)).hexdigest(),
            }
            for path in licence_names
        ]
        product_count = sum(n.startswith(namespace + "/") for n in names)
    metadata = distribution.read_text("METADATA")
    assert metadata is not None
    expected: dict[str, Json] = {
        "name": name,
        "version": distribution.version,
        "role": "direct",
        "source_kind": kind,
        "source_input_sha256": hashlib.sha256(
            json.dumps(response, sort_keys=True).encode()
        ).hexdigest(),
        "source_artifact": {
            "filename": wheel.name,
            "bytes": wheel.stat().st_size,
            "sha256": expected_hash,
            "kind": "bdist_wheel",
        },
        "owner_source": {
            "repository": "anulum/evidence-manifest-toolkit",
            "state": "owner_work_in_progress",
            "manifest": {k: reference(MANIFEST)[k] for k in ("bytes", "sha256")},
            "source_file_count": len(manifest["files"]),
            "product_source_prefix": "src/" + namespace if common else None,
            "product_namespace": namespace,
            "product_file_count": product_count,
            "build_inputs": [
                {k: reference(path)[k] for k in ("bytes", "sha256")} for path in build_inputs
            ],
        },
        "metadata_sha256": hashlib.sha256(metadata.encode()).hexdigest(),
        "metadata_version": distribution.metadata.get("Metadata-Version"),
        "requires_python": distribution.metadata.get("Requires-Python"),
        "requires_dist": cast(list[Json], distribution.requires or []),
        "license_expression": distribution.metadata.get("License-Expression"),
        "license_label": distribution.metadata.get("License"),
        "license_classifiers": [
            item
            for item in distribution.metadata.get_all("Classifier") or []
            if item.startswith("License ::")
        ],
        "license_files": licences,
    }
    return expected, response


def reconstruct(
    expected: dict[str, Json],
    response: dict[str, Json],
    *,
    artifacts: Path | None = ARTIFACTS,
    owner: Path | None = OWNER,
) -> dict[str, Json]:
    """Invoke the genuine public record boundary with independently supplied roots."""
    name = cast(str, expected["name"])
    digest = hashlib.sha256(json.dumps(response, sort_keys=True).encode()).hexdigest()
    return package_record(expected, {name: (digest, response)}, artifacts=artifacts, owner=owner)


def test_actual_local_source_record_has_no_invented_registry(
    local_source: tuple[dict[str, Json], dict[str, Json]],
) -> None:
    """Whole genuine wheels, source files and native licences reproduce exactly."""
    expected, response = local_source
    assert reconstruct(expected, response) == expected
    assert "official_metadata_sha256" not in expected
    assert "url" not in cast(dict[str, Json], expected["source_artifact"])


@pytest.mark.parametrize("missing", ["artifacts", "owner"])
def test_missing_independent_source_roots_refuse(
    local_source: tuple[dict[str, Json], dict[str, Json]],
    missing: str,
) -> None:
    """Missing source supply is unavailable, without an implicit registry replacement."""
    expected, response = local_source
    with pytest.raises(Fault) as raised:
        reconstruct(
            expected,
            response,
            artifacts=None if missing == "artifacts" else ARTIFACTS,
            owner=None if missing == "owner" else OWNER,
        )
    assert raised.value.exit_code == 3


@pytest.mark.parametrize(
    "field",
    [
        "name",
        "version",
        "metadata_sha256",
        "requires_python",
        "requires_dist",
        "metadata_version",
        "license_expression",
        "license_label",
        "license_classifiers",
    ],
)
def test_changed_selected_metadata_refuses(
    local_source: tuple[dict[str, Json], dict[str, Json]],
    field: str,
) -> None:
    """A selected record cannot relabel actual installed identity or metadata fields."""
    expected, response = local_source
    expected[field] = [] if field in {"requires_dist", "license_classifiers"} else "different"
    if field in {"requires_dist", "license_classifiers"} and not cast(
        list[Json], local_source[0][field]
    ):
        expected[field] = ["different"]
    with pytest.raises(Fault):
        reconstruct(expected, response)


@pytest.mark.parametrize(
    "change", ["official", "kind", "packet", "wheel-url", "owner", "count", "build", "role"]
)
def test_local_source_shape_and_evidence_refuse(
    local_source: tuple[dict[str, Json], dict[str, Json]],
    change: str,
) -> None:
    """Unknown source branches and missing or changed original evidence remain refusals."""
    expected, response = local_source
    if change == "official":
        expected["official_metadata_sha256"] = "0" * 64
    elif change == "kind":
        expected["source_kind"] = "unknown"
    elif change == "packet":
        response["received_callback"] = "never executed"
    elif change == "wheel-url":
        cast(dict[str, Json], expected["source_artifact"])["url"] = "https://example.invalid"
    elif change == "owner":
        cast(dict[str, Json], expected["owner_source"])["state"] = "unverified"
    elif change == "role":
        expected["role"] = "unreviewed-role"
    elif change == "count":
        cast(dict[str, Json], expected["owner_source"])["source_file_count"] = 1
    else:
        cast(dict[str, Json], expected["owner_source"])["build_inputs"] = []
    with pytest.raises(Fault):
        reconstruct(expected, response)


@pytest.mark.parametrize("change", ["missing", "bytes", "record", "product", "extra", "duplicate"])
def test_genuine_wheel_corruption_refuses(
    local_source: tuple[dict[str, Json], dict[str, Json]],
    tmp_path: Path,
    change: str,
) -> None:
    """Adverse derivatives of the actual wheel never change the retained original."""
    expected, response = local_source
    wheel_ref = cast(dict[str, Json], response["wheel"])
    original = ARTIFACTS / cast(str, wheel_ref["path"])
    before = original.read_bytes()
    destination = tmp_path / original.name
    if change == "bytes":
        destination.write_bytes(before[:-1])
    elif change not in {"missing"}:
        with zipfile.ZipFile(original) as archive, zipfile.ZipFile(destination, "w") as output:
            for name in archive.namelist():
                raw = archive.read(name)
                if change == "record" and name.endswith(".dist-info/RECORD"):
                    raw = raw.replace(b"sha256=", b"sha256=changed", 1)
                if change == "product" and name.endswith("/__init__.py"):
                    raw += b"\nchanged = True\n"
                output.writestr(name, raw)
            if change == "extra":
                output.writestr("unrecorded-source.py", b"unrecorded = True\n")
            if change == "duplicate":
                with pytest.warns(UserWarning, match="Duplicate name"):
                    output.writestr(archive.namelist()[0], archive.read(archive.namelist()[0]))
    wheel_ref["path"] = destination.relative_to(ARTIFACTS).as_posix()
    if destination.exists() and change != "bytes":
        artifact = cast(dict[str, Json], expected["source_artifact"])
        for key, value in reference(destination).items():
            if key != "path":
                artifact[key] = value
                wheel_ref[key] = value
    expected["source_input_sha256"] = hashlib.sha256(
        json.dumps(response, sort_keys=True).encode()
    ).hexdigest()
    with pytest.raises(Fault):
        reconstruct(expected, response)
    assert original.read_bytes() == before


@pytest.mark.parametrize("variable", ["PROVENANCE_ARTIFACTS", "PROVENANCE_OWNER_SOURCE"])
@pytest.mark.parametrize(
    "target",
    [
        "prepare-provenance-inputs",
        "provenance-generate",
        "provenance-verify",
    ],
)
def test_make_missing_local_root_stops_before_outputs(
    root: Path,
    tmp_path: Path,
    variable: str,
    target: str,
) -> None:
    """Real Make targets forward unavailable local roots before capture or publication."""
    missing = tmp_path / "missing-source"
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            target,
            "PYTHON=" + sys.executable,
            variable + "=" + str(missing),
        ],
        cwd=root,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 2, (result.stdout, result.stderr)
    report = json.loads(result.stdout.splitlines()[-1])
    assert report["exit_code"] == 3 and report["status"] == "unavailable"
    assert not missing.exists()
    assert not (root / ".tool-cache/provenance-inputs").exists()
    assert not (root / ".tool-cache/dependency-provenance.prospective.json").exists()
