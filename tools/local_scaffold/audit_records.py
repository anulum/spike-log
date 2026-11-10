# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Validate closed private audit records and the complete native audit semantics."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from packaging.utils import canonicalize_name

from .audit_context import ADVISORY_SOURCE, REGISTRY_GRAPH, context
from .audit_store import LOCATION, AdmissionStore
from .inputs import Json, parse_json
from .policy import EXPECTED_GRAPH
from .reports import DiagnosticLimit, Fault, Report

HEAD_SCHEMA = "spike_log.local-audit-admission-head.v1"
RECEIPT_SCHEMA = "spike_log.local-registry-audit-admission-receipt.v1"
DIGESTS = (
    "registry_graph_sha256",
    "trusted_policy_sha256",
    "installed_metadata_sha256",
    "python_executable_sha256",
    "installation_sha256",
    "stdout_sha256",
    "stderr_sha256",
)
FIELDS = {
    "schema",
    "generation",
    "producer",
    "producer_version",
    "advisory_source",
    "outcome",
    "native_exit",
    "started_at",
    "produced_at",
    "registry_graph_sha256",
    "trusted_policy_sha256",
    "installed_metadata_sha256",
    "python_version",
    "python_executable_sha256",
    "audit_sha256",
    "stdout_sha256",
    "stderr_sha256",
    "component_count",
    "installation_sha256",
}


def audit(data: bytes, report: Report) -> int:
    """Validate the exact native registry JSON cohort, duplicates, findings and fixes.

    Parameters
    ----------
    data : bytes
        Complete original native pip-audit JSON bytes.
    report : Report
        Receives all actual graph/producer/vulnerability refusals under existing precedence.

    Returns
    -------
    int
        Actual bounded input component count, including adverse duplicates and extras.

    Raises
    ------
    Fault
        Raised for malformed or unbounded native JSON/shape.
    """
    value = parse_json(data, ".tool-cache/security/pip-audit.json")
    if not isinstance(value, dict) or set(value) != {"dependencies", "fixes"}:
        raise Fault("configuration_invalid", LOCATION, 4)
    dependencies = value["dependencies"]
    if not isinstance(dependencies, list):
        raise Fault("configuration_invalid", LOCATION, 4)
    if len(dependencies) > 4096:
        raise Fault("resource_limit", LOCATION)
    actual: dict[str, str] = {}
    try:
        for dependency in dependencies:
            if not isinstance(dependency, dict) or set(dependency) != {"name", "version", "vulns"}:
                report.add("policy_refusal", LOCATION)
                continue
            name, version = dependency["name"], dependency["version"]
            if not isinstance(name, str) or not isinstance(version, str):
                report.add("policy_refusal", LOCATION)
                continue
            key = canonicalize_name(name)
            if key in actual or dependency["vulns"] != []:
                report.add("policy_refusal", LOCATION)
            actual[key] = version
        if actual != REGISTRY_GRAPH or value["fixes"] != []:
            report.add("dependency_alignment.wrong-producer", LOCATION)
    except DiagnosticLimit:
        # The report retains its explicit budget refusal; the raw population remains evidence.
        pass
    return len(dependencies)


def timestamp(value: Json) -> datetime:
    """Parse an actual aware producer timestamp without coercion or clock substitution.

    Parameters
    ----------
    value : Json
        Receipt timestamp string; missing, naive and malformed values refuse.

    Returns
    -------
    datetime
        Original aware producer time.

    Raises
    ------
    Fault
        Raised for invalid producer time syntax or timezone.
    """
    try:
        result = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        result = None
    if result is None or result.tzinfo is None:
        raise Fault("configuration_invalid", LOCATION, 4)
    return result


def object_digest(value: Json) -> str:
    """Validate an immutable object digest before typed store access.

    Parameters
    ----------
    value : Json
        Original receipt value without string coercion.

    Returns
    -------
    str
        Complete lowercase SHA-256 digest identifying retained bytes.

    Raises
    ------
    Fault
        Raised for non-string or malformed digest values.
    """
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise Fault("configuration_invalid", LOCATION, 4)
    return value


def receipt(store: AdmissionStore) -> dict[str, Json]:
    """Read and fully validate the latest terminal receipt without writing trust.

    Parameters
    ----------
    store : AdmissionStore
        Trusted installation store held under a shared lease.

    Returns
    -------
    dict of str to Json
        Complete admitted clean receipt; other terminal outcomes remain refusals.

    Raises
    ------
    Fault
        Raised for incomplete/invalid/adverse/expired/foreign-source admission.
    """
    head = parse_json(store.read("HEAD.json"), LOCATION)
    if not isinstance(head, dict) or set(head) != {
        "schema",
        "generation",
        "state",
        "receipt_sha256",
    }:
        raise Fault("configuration_invalid", LOCATION, 4)
    generation = head["generation"]
    if (
        head["schema"] != HEAD_SCHEMA
        or not isinstance(generation, str)
        or re.fullmatch(r"[a-f0-9]{32}", generation) is None
    ):
        raise Fault("configuration_invalid", LOCATION, 4)
    if head["state"] == "pending" and head["receipt_sha256"] is None:
        raise Fault("tool_unavailable", LOCATION, 3)
    selector = head["receipt_sha256"]
    if head["state"] != "terminal" or not isinstance(selector, str):
        raise Fault("configuration_invalid", LOCATION, 4)
    value = parse_json(store.read(selector, object_file=True), LOCATION)
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise Fault("configuration_invalid", LOCATION, 4)
    if value["schema"] != RECEIPT_SCHEMA or value["generation"] != generation:
        raise Fault("configuration_invalid", LOCATION, 4)
    for key in DIGESTS:
        object_digest(value[key])
    if value["producer"] != "pip-audit" or value["producer_version"] != EXPECTED_GRAPH["pip-audit"]:
        raise Fault("dependency_alignment.wrong-producer", LOCATION)
    advisory_source = value["advisory_source"]
    if not isinstance(advisory_source, dict) or set(advisory_source) != set(ADVISORY_SOURCE):
        raise Fault("configuration_invalid", LOCATION, 4)
    if advisory_source != ADVISORY_SOURCE:
        raise Fault("dependency_alignment.wrong-producer", LOCATION)
    count, native = value["component_count"], value["native_exit"]
    if (
        type(count) is not int
        or not 0 <= count <= 4096
        or (native is not None and type(native) is not int)
    ):
        raise Fault("configuration_invalid", LOCATION, 4)
    if not isinstance(value["python_version"], str) or len(value["python_version"]) > 32:
        raise Fault("configuration_invalid", LOCATION, 4)
    if value["outcome"] not in ("clean", "refused", "unavailable", "invalid"):
        raise Fault("configuration_invalid", LOCATION, 4)
    audit_selector = value["audit_sha256"]
    if audit_selector is not None and (
        not isinstance(audit_selector, str) or re.fullmatch(r"[a-f0-9]{64}", audit_selector) is None
    ):
        raise Fault("configuration_invalid", LOCATION, 4)
    for key, actual in context().items():
        if value[key] != actual:
            raise Fault("source_identity_mismatch", LOCATION)
    started = timestamp(value["started_at"])
    completed = None if value["produced_at"] is None else timestamp(value["produced_at"])
    if completed is not None and started > completed:
        raise Fault("configuration_invalid", LOCATION, 4)
    if value["outcome"] == "invalid":
        raise Fault("configuration_invalid", LOCATION, 4)
    if value["outcome"] == "unavailable":
        raise Fault("tool_unavailable", LOCATION, 3)
    if value["outcome"] == "refused":
        raise Fault("policy_refusal", LOCATION)
    if native != 0 or count != len(REGISTRY_GRAPH) or completed is None:
        raise Fault("configuration_invalid", LOCATION, 4)
    if not isinstance(audit_selector, str) or re.fullmatch(r"[a-f0-9]{64}", audit_selector) is None:
        raise Fault("configuration_invalid", LOCATION, 4)
    age = datetime.now(UTC) - completed
    if age > timedelta(days=1) or age < -timedelta(minutes=5):
        raise Fault("tool_unavailable", LOCATION, 3)
    for key in ("audit_sha256", "stdout_sha256", "stderr_sha256"):
        selector = object_digest(value[key])
        store.read(selector, object_file=True)
    if value["stdout_sha256"] != audit_selector:
        raise Fault("configuration_invalid", LOCATION, 4)
    return value
