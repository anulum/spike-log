# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Validate the exact local identity, trusted schema, lock and real interpreter."""

from __future__ import annotations

import hashlib
import importlib.metadata
import platform
import re
import sys
from email.parser import HeaderParser
from pathlib import Path
from typing import cast

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name

from .inputs import Json, json_object, parse_json, read_bytes
from .policy import (
    EXPECTED_GRAPH,
    GROUP,
    LIFECYCLE,
    LOCK_SHA256,
    PLANNED,
    PROFILE,
    PUBLIC_REMOTE,
    REPOSITORY,
    SCHEMA_SHA256,
)
from .production_names import check_values
from .reports import Fault, Report


def matches_fixed_shape(value: Json, rule: dict[str, Json]) -> bool:
    """Apply only the constructs in the hash-bound, closed metadata schema.

    Every object in that exact schema has all properties required and forbids
    additional properties. Its remaining rules are constants, empty arrays and
    constrained strings. Received schemas cannot extend this fixed language.

    Parameters
    ----------
    value : Json
        Decoded candidate metadata node, inspected against the admitted closed rule.
    rule : dict[str, Json]
        Hash-bound schema rule using only the supported fixed schema constructs.

    Returns
    -------
    bool
        True only when every supported rule constraint and closed object/array member shape matches.
    """
    if "const" in rule:
        return value == rule["const"]
    if rule["type"] == "object":
        if not isinstance(value, dict):
            return False
        properties = cast(dict[str, dict[str, Json]], rule["properties"])
        return set(value) == set(cast(list[str], rule["required"])) and all(
            matches_fixed_shape(value[name], child) for name, child in properties.items()
        )
    if rule["type"] == "array":
        return isinstance(value, list) and len(value) <= cast(int, rule["maxItems"])
    return (
        isinstance(value, str)
        and len(value) >= cast(int, rule.get("minLength", 0))
        and ("pattern" not in rule or re.search(cast(str, rule["pattern"]), value) is not None)
    )


def installed_graph() -> dict[str, str]:
    """Read actual producer identity headers from full installed METADATA bytes.

    Returns
    -------
    dict[str, str]
        Unique canonical installed distribution names and versions read from complete native METADATA headers.

    Raises
    ------
    Fault
        Raised for missing/invalid producer identity headers or duplicate canonical distribution names.
    """
    graph: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        raw_metadata = distribution.read_text("METADATA")
        if raw_metadata is None:
            raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json")
        metadata = HeaderParser().parsestr(raw_metadata.partition("\n\n")[0], headersonly=True)
        name, version = metadata.get("Name"), metadata.get("Version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json")
        key = canonicalize_name(name)
        if key in graph:
            raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json")
        graph[key] = version
    return graph


def check(root: Path, report: Report) -> dict[str, Json] | None:
    """Validate independent metadata inputs; generated inventory is never required.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives independent identity/maturity/schema/version/lock/installed-producer mismatches; inventory is not an input.

    Returns
    -------
    dict[str, Json] | None
        Decoded repository metadata after checking its independent bindings; callers must also inspect report.exit_code before admission.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable/unbounded or malformed independent metadata inputs.
    """
    metadata = json_object(root, "repository-domain.json")
    check_values(metadata, "repository-domain.json", report)
    checks: list[tuple[str, object, object]] = [
        ("wrong-identity", metadata.get("repository_name"), REPOSITORY),
        ("wrong-identity", metadata.get("owner_group"), GROUP),
        ("wrong-profile", metadata.get("lifecycle"), LIFECYCLE),
        ("wrong-identity", metadata.get("public_remote"), PUBLIC_REMOTE),
        ("wrong-profile", metadata.get("evidence_maturity"), "architecture_only"),
        ("nonempty-capabilities", metadata.get("capabilities"), []),
        ("nonempty-claims", metadata.get("claims"), []),
        ("qualified-id", metadata.get("qualified_owned_schema_ids"), []),
        ("wrong-planned-set", metadata.get("planned_owned_schema_ids"), PLANNED),
        ("wrong-profile", metadata.get("validation_profile"), PROFILE),
        (
            "wrong-profile",
            metadata.get("domain_runtime_dependencies"),
            ["evidence-manifest-toolkit==0.0.0.dev0"],
        ),
    ]
    for condition, actual, expected in checks:
        if actual != expected:
            report.add("repository_metadata." + condition, "repository-domain.json")
    expected_keys = {
        "tooling_python",
        *(
            key
            for key in (
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
                "domain_runtime_dependencies",
            )
        ),
    }
    if set(metadata) != expected_keys:
        report.add("repository_metadata.unknown-field", "repository-domain.json")
    schema_data = read_bytes(root, "schemas/repository-domain.schema.json")
    if hashlib.sha256(schema_data).hexdigest() != SCHEMA_SHA256:
        report.add("repository_metadata.malicious-schema", "schemas/repository-domain.schema.json")
    else:
        schema = cast(
            dict[str, Json], parse_json(schema_data, "schemas/repository-domain.schema.json")
        )
        if not matches_fixed_shape(metadata, schema):
            report.add("repository_metadata.wrong-types", "repository-domain.json")
    lock_digest = hashlib.sha256(read_bytes(root, "requirements-dev.txt")).hexdigest()
    tooling = metadata.get("tooling_python")
    if not isinstance(tooling, dict) or set(tooling) != {
        "design_baseline",
        "actual_version",
        "supported_range",
        "development_lock_sha256",
    }:
        report.add("repository_metadata.wrong-types", "repository-domain.json")
    else:
        if (
            tooling["design_baseline"] != "3.13"
            or tooling["actual_version"] != platform.python_version()
        ):
            report.add("repository_metadata.bad-version", "repository-domain.json")
        if sys.version_info[:2] != (3, 13):
            report.add("repository_metadata.bad-version", "repository-domain.json")
        specifier = tooling["supported_range"]
        if not isinstance(specifier, str):
            report.add("repository_metadata.bad-specifier", "repository-domain.json")
        else:
            try:
                supported = SpecifierSet(specifier)
                if not specifier or platform.python_version() not in supported:
                    report.add("repository_metadata.bad-version", "repository-domain.json")
            except InvalidSpecifier:
                report.add("repository_metadata.bad-specifier", "repository-domain.json")
        if tooling["development_lock_sha256"] != lock_digest:
            report.add("repository_metadata.lock-drift", "requirements-dev.txt")
    if lock_digest != LOCK_SHA256:
        report.add("repository_metadata.lock-drift", "requirements-dev.txt")
    graph = installed_graph()
    if graph != EXPECTED_GRAPH:
        report.add("repository_metadata.installed-graph-drift", "dependency-provenance.json")
    return metadata


def verify(root: Path, report: Report) -> None:
    """Apply the public metadata gate and retain safe locating input faults.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives the metadata check's findings and safely located input faults.
    """
    try:
        check(root, report)
    except Fault as fault:
        report.observe(fault)
