# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Metadata conformance through genuine public CLI and actual installed tooling."""

import copy
import json
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, change, closed_stdout, payload, run_guard, snapshots

ARRAY_TYPE_REPLACEMENTS: tuple[Json, ...] = (None, {}, "")


def test_actual_metadata_input_symlink_is_refused(root: Path, tmp_path: Path) -> None:
    """A linked original metadata file cannot bypass the public no-follow boundary."""
    path = root / "repository-domain.json"
    original = path.read_bytes()
    retained = tmp_path / "retained-original-repository-domain.json"
    path.rename(retained)
    path.symlink_to(retained)
    before = snapshots(root)
    result = payload(run_guard("repository_metadata", root), 2)
    assert result["reasons"] == [
        {
            "code": "repository_inventory.symlink-entry",
            "location": "repository-domain.json",
            "detail": "Required local infrastructure condition failed: repository_inventory.symlink-entry.",
        }
    ]
    assert snapshots(root) == before
    assert path.is_symlink() and retained.read_bytes() == original


REQUIRED_MEMBERS: Sequence[tuple[str, ...]] = (
    [
        (name,)
        for name in (
            "repository_name",
            "owner_group",
            "lifecycle",
            "public_remote",
            "evidence_maturity",
            "capabilities",
            "claims",
            "qualified_owned_schema_ids",
            "planned_owned_schema_ids",
            "validation_profile",
            "tooling_python",
            "domain_runtime_dependencies",
        )
    ]
    + [
        ("validation_profile", name)
        for name in (
            "id",
            "revision",
            "standard_sha256",
            "profile_sha256",
        )
    ]
    + [
        ("tooling_python", name)
        for name in (
            "design_baseline",
            "actual_version",
            "supported_range",
            "development_lock_sha256",
        )
    ]
)


@pytest.mark.parametrize("path", REQUIRED_MEMBERS)
def test_every_required_schema_member(root: Path, path: tuple[str, ...]) -> None:
    """Remove every actual required member and compare public shape refusal."""
    filename = root / "repository-domain.json"
    value = cast(dict[str, Json], json.loads(filename.read_bytes()))
    parent = value
    for key in path[:-1]:
        parent = cast(dict[str, Json], parent[key])
    del parent[path[-1]]
    filename.write_text(json.dumps(value) + "\n")
    before = snapshots(root)
    report = payload(run_guard("repository_metadata", root), 2)
    assert b"repository_metadata.wrong-types" in json.dumps(report).encode()
    assert snapshots(root) == before


SHAPE_MUTATIONS: list[tuple[tuple[str, ...], Json]] = [
    (("validation_profile",), []),
    (("validation_profile",), None),
    (("tooling_python",), []),
    (("tooling_python",), True),
    (("validation_profile", "extra"), "untrusted"),
    (("tooling_python", "extra"), "untrusted"),
    (("tooling_python", "actual_version"), "3.13.016"),
    (("tooling_python", "actual_version"), "3x13x16"),
    (("tooling_python", "development_lock_sha256"), "A" * 64),
    (("tooling_python", "development_lock_sha256"), "a" * 63),
    (("tooling_python", "development_lock_sha256"), 64),
] + [
    ((name,), replacement)
    for name in (
        "capabilities",
        "claims",
        "qualified_owned_schema_ids",
        "domain_runtime_dependencies",
    )
    for replacement in ARRAY_TYPE_REPLACEMENTS
]


@pytest.mark.parametrize(("path", "replacement"), SHAPE_MUTATIONS)
def test_fixed_schema_matches_native_shape_refusal(
    root: Path, path: tuple[str, ...], replacement: Json
) -> None:
    """Observe genuine public schema type, closure and pattern refusals."""
    change(root, "repository-domain.json", path, replacement)
    before = snapshots(root)
    report = payload(run_guard("repository_metadata", root), 2)
    assert b"repository_metadata.wrong-types" in json.dumps(report).encode()
    assert snapshots(root) == before


def test_complete_genuine_schema_oracle() -> None:
    """Independently validate every tested mutation with the genuine Draft oracle."""
    from jsonschema import Draft202012Validator

    schema = json.loads((SOURCE / "schemas/repository-domain.schema.json").read_bytes())
    original = json.loads((SOURCE / "repository-domain.json").read_bytes())
    validator = Draft202012Validator(schema)
    assert validator.is_valid(original)
    for path in REQUIRED_MEMBERS:
        value = copy.deepcopy(original)
        parent = value
        for key in path[:-1]:
            parent = parent[key]
        del parent[path[-1]]
        assert not validator.is_valid(value), path
    for path, replacement in SHAPE_MUTATIONS:
        value = copy.deepcopy(original)
        parent = value
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = replacement
        assert not validator.is_valid(value), path


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("repository_name",), "FOREIGN-REPOSITORY"),
        (("owner_group",), "FOREIGN"),
        (("unknown",), "private-sentinel"),
        (("tooling_python", "actual_version"), True),
        (("capabilities",), ["verify"]),
        (("claims",), ["qualified"]),
        (("qualified_owned_schema_ids",), ["spike_log.container.v1"]),
        (("planned_owned_schema_ids",), []),
        (("lifecycle",), "implemented"),
        (("lifecycle",), "local_scaffold"),
        (("public_remote",), "https://github.com/anulum/other-repository"),
        (("public_remote",), "https://github.com/anulum/SPIKE-LOG"),
        (("evidence_maturity",), "qualified"),
        (("validation_profile", "revision"), "old"),
        (
            ("validation_profile", "standard_sha256"),
            "4ef4464d75cc7d09938446b4199de3b9b775a1c5a0ef3748d2ce6ec77d87bcb5",
        ),
        (
            ("validation_profile", "standard_sha256"),
            "202ba18afd79bcad0d0d9722f6d83910bec3493587b935632d1449ce668063ca",
        ),
        (
            ("validation_profile", "profile_sha256"),
            "40c824b187245c419a5bb710a9d2fefa8d3a92ff1613d879c9908e7545a88b57",
        ),
        (
            ("validation_profile", "standard_sha256"),
            "4b7dbc427bc51f1ba93bd877c0afa6d44d6f39beb6981897439483c9dcfed96f",
        ),
        (
            ("validation_profile", "profile_sha256"),
            "a399d0176a2dfa634983cb87ffb1c06a6d7aa354a33cbde0b247be1823577322",
        ),
        (("validation_profile", "profile_sha256"), "0" * 64),
        (("tooling_python", "actual_version"), "3.13.01"),
        (("tooling_python", "design_baseline"), "3.14"),
        (("tooling_python", "supported_range"), "invalid"),
        (("tooling_python", "supported_range"), ""),
        (("tooling_python", "supported_range"), ">=4"),
        (("tooling_python", "supported_range"), True),
        (("tooling_python",), {}),
        (("domain_runtime_dependencies",), ["unimplemented-runtime"]),
    ],
)
def test_closed_identity(root: Path, path: tuple[str, ...], replacement: Json) -> None:
    """Refuse each independently authored identity/state/type/compatibility fault."""
    change(root, "repository-domain.json", path, replacement)
    result = run_guard("repository_metadata", root)
    payload(result, 2)
    assert b"private-sentinel" not in result.stdout


def test_valid_without_output(root: Path) -> None:
    """Metadata acceptance is deterministic and independent of generated output."""
    (root / "capability-inventory.json").unlink()
    before = snapshots(root)
    first = run_guard("repository_metadata", root)
    second = run_guard("repository_metadata", root)
    payload(first, 0)
    assert first.stdout == second.stdout
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "data",
    [
        b'{"repository_name":"SPIKE-LOG","repository_name":"SPIKE-LOG"}',
        b'{"private-sentinel":NaN}',
        b'{"private-sentinel":Infinity}',
        b'{"private-sentinel":1e400}',
        b'{"private-sentinel":"\\ud800"}',
        b'{"private-sentinel":"\\u001b"}',
        b"\xff",
        b"null",
        b"[]",
        b"{",
        b"[" * 65 + b"0" + b"]" * 65,
        b'{"value":"' + b"x" * 65537 + b'"}',
        b" " * 1048577,
        b'"' + b'\\"' * 200000 + b"\\",
        b'"' + b'\\"' * 200000 + b'"',
    ],
    ids=[
        "duplicate",
        "nan",
        "infinity",
        "overflow",
        "surrogate",
        "escaped-control",
        "utf8",
        "null",
        "array",
        "syntax",
        "depth",
        "string",
        "raw-size",
        "unterminated-escaped-string",
        "oversized-escaped-string",
    ],
)
def test_strict_finite_json(root: Path, data: bytes) -> None:
    """Exercise actual raw parser refusals without echoing received values."""
    (root / "repository-domain.json").write_bytes(data)
    result = run_guard("repository_metadata", root)
    payload(result, 2)
    assert b"private-sentinel" not in result.stdout


def test_multiple_failures(root: Path) -> None:
    """Preserve both independent state violations instead of first-error acceptance."""
    change(root, "repository-domain.json", ("capabilities",), ["runtime"])
    change(root, "repository-domain.json", ("claims",), ["qualified"])
    result = payload(run_guard("repository_metadata", root), 2)
    assert isinstance(result["reasons"], list)
    assert len(result["reasons"]) >= 2


def test_quoted_structures_preserve_actual_depth(root: Path) -> None:
    """Quoted delimiters and escaped quotes cannot invent a structural limit."""
    import json

    change(root, "repository-domain.json", ("unknown",), '[{\\"' * 100)
    report = payload(run_guard("repository_metadata", root), 2)
    reasons = cast(list[dict[str, Json]], report["reasons"])
    codes = [reason["code"] for reason in reasons]
    assert "repository_metadata.unknown-field" in codes
    assert "resource_limit" not in codes
    assert b"unknown" in json.dumps(report).encode()


def test_schema_cannot_weaken_policy(root: Path) -> None:
    """A permissive caller-supplied schema cannot replace the trusted design."""
    (root / "schemas/repository-domain.schema.json").write_text("{}\n")
    result = run_guard("repository_metadata", root)
    payload(result, 2)
    assert b"malicious-schema" in result.stdout


def test_raw_lock_drift(root: Path) -> None:
    """Even whitespace changes require the actual lock/source digest to agree."""
    path = root / "requirements-dev.txt"
    path.write_bytes(path.read_bytes() + b"\n")
    result = run_guard("repository_metadata", root)
    payload(result, 2)
    assert b"lock-drift" in result.stdout


def test_invocation_and_roots(root: Path, tmp_path: Path) -> None:
    """Unknown options, absent roots and real symbolic roots preserve native exits."""
    payload(run_guard("repository_metadata", tmp_path / "absent"), 3)
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    payload(run_guard("repository_metadata", link), 2)
    result = run_guard("repository_metadata", root, "--private-sentinel")
    payload(result, 4)
    assert b"private-sentinel" not in result.stdout


def test_missing_input_and_closed_consumer(root: Path) -> None:
    """Required input absence and a broken real pipe never return success."""
    (root / "repository-domain.json").unlink()
    payload(run_guard("repository_metadata", root), 3)
    assert closed_stdout("repository_metadata", root) != 0
