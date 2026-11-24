# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Run the installed one-shot registry capture under its parent deadline."""

from __future__ import annotations

import hashlib
import json
import platform
import signal
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from typing import cast

from .cli import interrupted, retain_fault
from .inputs import (
    Json,
    json_object,
    parse_json,
    read_bytes,
    relative_path,
    require_byte_budget,
    root_directory,
)
from .policy import MAX_INPUT, PROVENANCE_SHA256
from .reports import DiagnosticLimit, Fault, Report


def capture_once(
    root: Path,
    name: str,
    report: Report,
    *,
    artifacts: Path | None = None,
    owner: Path | None = None,
) -> None:
    """Capture registry responses or revalidate a complete prepared source cohort.

    Parameters
    ----------
    root : Path
        Actual repository whose fixed baseline and installed graph are checked first.
    name : str
        Repository-relative snapshot directory; an incomplete existing directory is retained and refused.
    report : Report
        Receives repository failures; capture itself never produces trusted audit evidence.

    artifacts : Path | None
        Explicit local artifact root for revalidating a complete prepared cohort.
    owner : Path | None
        Explicit owner source tree; local wheel sources are never fetched from PyPI.

    Raises
    ------
    Fault
        Raised for unavailable transport, incomplete input, invalid source identity or failed publication.
    DiagnosticLimit
        Raised when source validation fills the supplied report's diagnostic budget.
    """
    from .inventory import publish
    from .metadata import check
    from .provenance_local import LOCAL_KINDS
    from .provenance_reproduction import package_record
    from .provenance_sources import SourceResponses, check_direct_requirements, load

    check(root, report)
    if report.exit_code:
        return
    original = read_bytes(root, "dependency-provenance.json")
    if hashlib.sha256(original).hexdigest() != PROVENANCE_SHA256:
        raise Fault("source_identity_mismatch", "dependency-provenance.json")
    baseline = cast(dict[str, Json], parse_json(original, "dependency-provenance.json"))
    check_direct_requirements(root)
    packages = cast(list[dict[str, Json]], baseline["packages"])
    directory = relative_path(root, name)
    if directory.exists():
        sources = load(directory)
        for record in packages:
            package_record(record, sources, artifacts=artifacts or directory, owner=owner)
        return
    for record in packages:
        kind = record.get("source_kind")
        if kind is not None:
            if not isinstance(kind, str) or kind not in LOCAL_KINDS:
                # No real input reaches this refusal while dependency-provenance.json is pinned to
                # PROVENANCE_SHA256 above: every source_kind of the pinned baseline is a local kind,
                # which test_every_pinned_baseline_source_kind_is_a_local_kind asserts. It guards a
                # future pin.
                raise Fault("configuration_invalid", "local-source", 4)  # pragma: no cover
            if artifacts is None or owner is None:
                raise Fault("input_unavailable", str(record["name"]), 3)
    try:
        directory.mkdir()
    except OSError as error:
        raise Fault("input_unavailable", name, 3) from error
    entries: list[Json] = []
    for record in packages:
        package = cast(str, record["name"])
        version = cast(str, record["version"])
        if "source_kind" in record:
            data = read_bytes(cast(Path, artifacts), package + ".json")
        else:
            data = _registry_response(package, version)
        require_byte_budget(len(data), MAX_INPUT)
        path = package + ".json"
        publish(directory, path, data)
        value = json_object(directory, path)
        digest = hashlib.sha256(data).hexdigest()
        current: SourceResponses = {package: (digest, value)}
        package_record(record, current, artifacts=artifacts, owner=owner)
        entries.append({"name": package, "version": version, "path": path, "sha256": digest})
    index: dict[str, Json] = {
        "input_schema": "spike_log.dependency-source-inputs.v2",
        "python": platform.python_version(),
        "lock_sha256": baseline["lock_sha256"],
        "packages": entries,
    }
    publish(directory, "inputs.json", (json.dumps(index, sort_keys=True, indent=2) + "\n").encode())
    load(directory)


def _registry_response(package: str, version: str) -> bytes:
    """Fetch one package version's complete raw metadata response from the registry.

    Parameters
    ----------
    package : str
        Canonical package name selected by the baseline.
    version : str
        Exact version selected by the baseline.

    Returns
    -------
    bytes
        The response body, read to at most one byte past the input budget.

    Raises
    ------
    Fault
        Raised as unavailable for any transport failure or a status other than 200.
    """
    connection = HTTPSConnection("pypi.org", timeout=10.0)
    try:
        connection.request(
            "GET",
            "/pypi/" + package + "/" + version + "/json",
            headers={"Accept": "application/json", "User-Agent": "SPIKE-LOG-provenance/1"},
        )
        with connection.getresponse() as response:
            if response.status != 200:
                raise Fault("tool_unavailable", exit_code=3)
            data = response.read(MAX_INPUT + 1)
    except (OSError, HTTPException) as error:
        raise Fault("tool_unavailable", exit_code=3) from error
    finally:
        connection.close()
    return data


def main(raw_root: str, name: str, raw_artifacts: str = "", raw_owner: str = "") -> int:
    """Emit one closed worker result after actual capture or source validation.

    Parameters
    ----------
    raw_root : str
        Inspected repository path supplied as data by the installed parent.
    name : str
        Root-relative snapshot destination, never an executable or source-module selector.

    raw_artifacts : str
        Optional explicit artifact directory, passed only as bounded source data.
    raw_owner : str
        Optional explicit owning source directory, never an executable selector.

    Returns
    -------
    int
        Native0/2/3/4 matching the complete provenance_inputs leaf report.
    """
    report = Report("provenance_reproduction", scope="provenance_inputs")
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        capture_once(
            root_directory(raw_root),
            name,
            report,
            artifacts=root_directory(raw_artifacts) if raw_artifacts else None,
            owner=root_directory(raw_owner) if raw_owner else None,
        )
    except Fault as fault:
        retain_fault(report, fault)
    except DiagnosticLimit:
        pass
    except (ImportError, ModuleNotFoundError):
        retain_fault(report, Fault("tool_unavailable", exit_code=3))
    except KeyboardInterrupt:
        retain_fault(report, Fault("interrupted", exit_code=3))
    except Exception:
        retain_fault(report, Fault("unexpected_fault"))
    finally:
        signal.signal(signal.SIGTERM, previous)
    return report.emit(True)
