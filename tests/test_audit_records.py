# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise adverse closed admission fields, real time boundaries and terminal states."""

import hashlib
import json
from pathlib import Path

import pytest

from local_scaffold.inputs import Json
from tests.conftest import adverse_audit_receipt, clone_dependency, payload, run_guard

RECEIPT_FAULTS: list[tuple[str, Json, int]] = [
    ("schema", "unknown", 4),
    ("schema", "spike_log.local-audit-admission-receipt.v1", 4),
    ("generation", "0" * 32, 4),
    ("component_count", False, 4),
    ("component_count", -1, 4),
    ("component_count", 4097, 4),
    ("component_count", 102, 4),
    ("native_exit", False, 4),
    ("native_exit", "0", 4),
    ("native_exit", 1, 4),
    ("python_version", 7, 4),
    ("python_version", "x" * 33, 4),
    ("outcome", "unknown", 4),
    ("outcome", "unavailable", 3),
    ("outcome", "refused", 2),
    ("outcome", "invalid", 4),
    ("started_at", "not-a-time", 4),
    ("started_at", "2026-10-01T00:00:00", 4),
    ("started_at", "2999-01-01T00:00:00+00:00", 4),
    ("produced_at", "not-a-time", 4),
    ("produced_at", "2026-10-01T00:00:00", 4),
    ("produced_at", None, 4),
    ("produced_at", "2999-01-01T00:00:00+00:00", 3),
    ("audit_sha256", None, 4),
    ("audit_sha256", "not-a-digest", 4),
    ("stdout_sha256", False, 4),
    ("stderr_sha256", None, 4),
    ("installed_metadata_sha256", 7, 4),
    ("stdout_sha256", "not-a-digest", 4),
    ("stderr_sha256", "not-a-digest", 4),
    ("installation_sha256", "not-a-digest", 4),
    ("stdout_sha256", "1" * 64, 3),
    ("stderr_sha256", "2" * 64, 3),
    ("audit_sha256", "3" * 64, 3),
]


@pytest.mark.parametrize(("field", "value", "expected"), RECEIPT_FAULTS)
def test_adverse_receipt_fields_refuse(
    audited_clone: Path, field: str, value: Json, expected: int
) -> None:
    """Mutated owned negative records cannot become current clean admission."""
    adverse_audit_receipt(audited_clone, {field: value})
    payload(clone_dependency(audited_clone), expected)


def test_expired_real_receipt_field_is_unavailable(audited_clone: Path) -> None:
    """Old adverse fixture times cannot retain the genuine record's current freshness."""
    adverse_audit_receipt(
        audited_clone,
        {
            "started_at": "1999-01-01T00:00:00+00:00",
            "produced_at": "2000-01-01T00:00:00+00:00",
        },
    )
    payload(clone_dependency(audited_clone), 3)


def test_clean_receipt_requires_original_audit_stdout(audited_clone: Path) -> None:
    """A different existing capture cannot replace the clean audit's original stdout."""
    store = audited_clone / ".tool-cache/security-admissions"
    head = json.loads((store / "HEAD.json").read_bytes())
    receipt = json.loads((store / "objects" / (head["receipt_sha256"] + ".json")).read_bytes())
    assert receipt["stdout_sha256"] != receipt["stderr_sha256"]
    adverse_audit_receipt(audited_clone, {"stdout_sha256": receipt["stderr_sha256"]})
    payload(clone_dependency(audited_clone), 4)


@pytest.mark.parametrize(
    ("value", "expected"),
    [([], 4), ({}, 4), ({"schema": "unknown"}, 4)],
)
def test_incomplete_head_shape_is_invalid(audited_clone: Path, value: Json, expected: int) -> None:
    """A received partial head cannot identify a valid terminal receipt."""
    (audited_clone / ".tool-cache/security-admissions/HEAD.json").write_text(json.dumps(value))
    payload(clone_dependency(audited_clone), expected)


@pytest.mark.parametrize(
    ("state", "selector", "expected"),
    [("pending", None, 3), ("pending", "0" * 64, 4), ("unknown", None, 4), ("terminal", None, 4)],
)
def test_pending_and_inconsistent_heads_refuse(
    audited_clone: Path, state: str, selector: Json, expected: int
) -> None:
    """Pending attempts cannot fall back to retained historical clean objects."""
    path = audited_clone / ".tool-cache/security-admissions/HEAD.json"
    head = json.loads(path.read_bytes())
    head.update({"state": state, "receipt_sha256": selector})
    path.write_text(json.dumps(head))
    payload(clone_dependency(audited_clone), expected)


@pytest.mark.parametrize(
    ("field", "value"),
    [("schema", "unknown"), ("generation", 7), ("generation", "invalid-generation")],
)
def test_complete_head_identity_and_generation_refuse(
    audited_clone: Path, field: str, value: Json
) -> None:
    """Malformed head identity refuses even when its adverse receipt generation agrees."""
    if field == "generation":
        adverse_audit_receipt(audited_clone, {"generation": value})
    path = audited_clone / ".tool-cache/security-admissions/HEAD.json"
    head = json.loads(path.read_bytes())
    head[field] = value
    path.write_text(json.dumps(head))
    record = payload(clone_dependency(audited_clone), 4)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "configuration_invalid" for reason in reasons
    )
    assert all(
        not isinstance(reason, dict) or reason["code"] != "unexpected_fault" for reason in reasons
    )


@pytest.mark.parametrize("value", [[], {}, {"schema": "unknown"}])
def test_terminal_receipt_requires_complete_object(audited_clone: Path, value: Json) -> None:
    """A digest-correct adverse object cannot substitute for the complete receipt schema."""
    store = audited_clone / ".tool-cache/security-admissions"
    path = store / "HEAD.json"
    head = json.loads(path.read_bytes())
    data = (json.dumps(value) + "\n").encode()
    selector = hashlib.sha256(data).hexdigest()
    (store / "objects" / (selector + ".json")).write_bytes(data)
    head["receipt_sha256"] = selector
    path.write_text(json.dumps(head))
    record = payload(clone_dependency(audited_clone), 4)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "configuration_invalid" for reason in reasons
    )
    assert all(
        not isinstance(reason, dict) or reason["code"] != "unexpected_fault" for reason in reasons
    )


@pytest.mark.parametrize("value", [[], {}, {"dependencies": [], "fixes": [], "extra": True}])
def test_native_audit_requires_closed_graph_object(root: Path, value: Json) -> None:
    """Received malformed graph bodies retain authored invalid-input precedence."""
    (root / ".tool-cache/security/pip-audit.json").write_text(json.dumps(value))
    record = payload(run_guard("dependency_alignment", root), 4)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "configuration_invalid" for reason in reasons
    )
    assert all(
        not isinstance(reason, dict) or reason["code"] != "unexpected_fault" for reason in reasons
    )


@pytest.mark.parametrize(
    ("count", "reason_code"), [(4097, "resource_limit"), (300, "diagnostic_budget_exceeded")]
)
def test_native_graph_component_and_diagnostic_bounds_refuse(
    root: Path, count: int, reason_code: str
) -> None:
    """Actual oversized and diagnosis-saturating graph files remain finite refusals."""
    path = root / ".tool-cache/security/pip-audit.json"
    value = json.loads(path.read_bytes())
    value["dependencies"] = [{} for _ in range(count)]
    path.write_text(json.dumps(value))
    record = payload(run_guard("dependency_alignment", root), 2)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(reason, dict) and reason["code"] == reason_code for reason in reasons)
    if count == 300:
        assert len(reasons) == 256
        assert isinstance(reasons[-1], dict) and reasons[-1]["code"] == reason_code
    assert all(
        not isinstance(reason, dict) or reason["code"] != "unexpected_fault" for reason in reasons
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (None, 4),
        ({}, 4),
        ({"service": "osv"}, 4),
        ({"service": "pypi", "url": "https://api.osv.dev/v1/query", "database_revision": None}, 2),
        ({"service": "osv", "url": "https://example.invalid", "database_revision": None}, 2),
        (
            {
                "service": "osv",
                "url": "https://api.osv.dev/v1/query",
                "database_revision": "invented",
            },
            2,
        ),
    ],
)
def test_unselected_advisory_sources_refuse(
    audited_clone: Path, source: Json, expected: int
) -> None:
    """Refuse altered source identity and fabricated database revisions through the CLI."""
    adverse_audit_receipt(audited_clone, {"advisory_source": source})
    record = payload(clone_dependency(audited_clone), expected)
    reasons = record["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict)
        and reason["code"]
        == ("configuration_invalid" if expected == 4 else "dependency_alignment.wrong-producer")
        for reason in reasons
    )
