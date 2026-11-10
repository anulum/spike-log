# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Consume a separately produced real pip-audit snapshot without network fallback."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .audit_context import trusted_root
from .audit_records import audit, object_digest, receipt, timestamp
from .audit_store import open_store
from .inputs import json_object, read_bytes
from .policy import AUDIT_PRODUCED_AT, AUDIT_SHA256, EXPECTED_GRAPH
from .reports import Report


def historical_source(root: Path, report: Report) -> None:
    """Verify immutable historical source admission without granting current freshness.

    Parameters
    ----------
    root : Path
        Inspected repository supplying the original immutable source declaration.
    report : Report
        Receives exact source identity and aware-time syntax refusals; received time cannot renew trust.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable/unbounded or malformed retained snapshot input.
    """
    source = "dependency-provenance.json"
    snapshot = json_object(root, source).get("security_audit")
    expected = {
        "producer": "pip-audit",
        "version": EXPECTED_GRAPH["pip-audit"],
        "sha256": AUDIT_SHA256,
        "produced_at": AUDIT_PRODUCED_AT,
    }
    if not isinstance(snapshot, dict) or set(snapshot) != set(expected):
        report.add("configuration_invalid", source, 4)
        return
    if snapshot != expected:
        report.add("source_identity_mismatch", source)
    timestamp(snapshot["produced_at"])


def verify(root: Path, report: Report) -> None:
    """Verify original audit semantics against independent current installation admission.

    Parameters
    ----------
    root : Path
        Inspected repository supplying audit bytes, never a local admission store or producer command.
    report : Report
        Receives source identity, complete graph/findings, current admission and freshness outcomes.

    Raises
    ------
    Fault
        Raised for missing/unsafe/malformed/adverse/expired trusted admission or received input.
    """
    historical_source(root, report)
    if report.exit_code == 4:
        return
    name = ".tool-cache/security/pip-audit.json"
    data = read_bytes(root, name)
    with open_store(trusted_root()) as store:
        current = receipt(store)
        selector = object_digest(current["audit_sha256"])
        retained = store.read(selector, object_file=True)
        if hashlib.sha256(data).hexdigest() != selector or data != retained:
            report.add("source_identity_mismatch", name)
        audit(data, report)
