# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Verify the two independently bound local producers without invented registry URLs."""

import importlib.metadata
from typing import cast

from .audit_context import trusted_root
from .inputs import Json, relative_path
from .provenance_local import LOCAL_KINDS
from .provenance_wheels import wheel_members
from .reports import Fault, Report


def check_local_dependency(record: dict[str, Json], lock: str, report: Report) -> None:
    """Check fixed local wheel identities and every actual installed member byte.

    Parameters
    ----------
    record : dict
        Package record from the independently hash-bound complete provenance.
    lock : str
        Whole selected dependency lock, with its independently bound hash.
    report : Report
        Receives malformed local identity, missing exact lock hash or WIP refusal.

    Raises
    ------
    Fault
        Required original local wheel or installed producer is unavailable or differs.

    Notes
    -----
    Complete committed source reproduction and independent source security review
    remain separate required qualification operations. Cached bytes cannot renew
    them, select an owner root or manufacture publisher metadata.
    """
    name, kind, source, artifact = (
        record.get(key) for key in ("name", "source_kind", "owner_source", "source_artifact")
    )
    if (
        name not in ("evidence-manifest-toolkit", "rfc8785")
        or not isinstance(kind, str)
        or kind not in LOCAL_KINDS
        or kind
        != ("first_party_wheel" if name == "evidence-manifest-toolkit" else "maintained_wheel")
        or not isinstance(source, dict)
        or source.get("state") != "committed"
        or not isinstance(source.get("product_namespace"), str)
        or not isinstance(artifact, dict)
        or set(artifact) != {"filename", "bytes", "sha256", "kind"}
    ):
        report.add("dependency_alignment.wrong-producer", "dependency-provenance.json")
        return
    if "--hash=sha256:" + str(artifact.get("sha256")) not in lock:
        report.add("dependency_alignment.missing-hash", "requirements-dev.txt")
        return
    try:
        distribution = importlib.metadata.distribution(cast(str, name))
    except importlib.metadata.PackageNotFoundError as error:
        raise Fault("dependency_alignment.wrong-producer", "dependency-provenance.json") from error
    wheel_members(
        relative_path(trusted_root(), ".tool-cache/environment-inputs"),
        artifact,
        distribution,
        namespace=cast(str, source["product_namespace"]),
    )
