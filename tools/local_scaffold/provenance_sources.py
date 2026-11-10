# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Load complete, byte-bound offline inputs for dependency provenance."""

from __future__ import annotations

import hashlib
import platform
from pathlib import Path
from typing import cast

from .inputs import Json, json_object, parse_json, read_bytes
from .policy import EXPECTED_GRAPH, LOCK_SHA256
from .reports import Fault

type SourceResponses = dict[str, tuple[str, dict[str, Json]]]

DIRECT_REQUIREMENTS_SHA256 = "475e8f7028ac119b3ca8faeb2edf3e341e1e0f35fa2121101b56423f25d6ed0e"


def check_direct_requirements(root: Path) -> None:
    """Require the exact authored direct requirements used by the fixed lock.

    Parameters
    ----------
    root : Path
        Repository supplying requirements-dev.in as a source input, not as a new expected identity.

    Raises
    ------
    Fault
        Raised when direct requirements are unavailable or differ from their reviewed source bytes.
    """
    data = read_bytes(root, "requirements-dev.in")
    if hashlib.sha256(data).hexdigest() != DIRECT_REQUIREMENTS_SHA256:
        raise Fault("source_identity_mismatch", "requirements-dev.in")


def load(directory: Path) -> SourceResponses:
    """Read every declared response in the complete locked source cohort.

    Parameters
    ----------
    directory : Path
        Offline snapshot directory containing inputs.json and its response files.

    Returns
    -------
    SourceResponses
        Canonical package names mapped to original response digests and parsed objects.

    Raises
    ------
    Fault
        Raised for unavailable input, invalid cohort shape, graph drift or response digest mismatch.
    """
    index = json_object(directory, "inputs.json")
    if (
        set(index) != {"input_schema", "python", "lock_sha256", "packages"}
        or index["input_schema"]
        not in ("spike_log.dependency-source-inputs.v1", "spike_log.dependency-source-inputs.v2")
        or index["python"] != platform.python_version()
        or index["lock_sha256"] != LOCK_SHA256
    ):
        raise Fault("source_identity_mismatch", "inputs.json")
    packages = index["packages"]
    if not isinstance(packages, list) or len(packages) != len(EXPECTED_GRAPH):
        raise Fault("policy_refusal", "inputs.json")
    result: SourceResponses = {}
    for value in packages:
        if (
            not isinstance(value, dict)
            or set(value) != {"name", "version", "path", "sha256"}
            or any(not isinstance(member, str) for member in value.values())
        ):
            raise Fault("configuration_invalid", "inputs.json", 4)
        entry = cast(dict[str, str], value)
        name = entry["name"]
        if name in result or EXPECTED_GRAPH.get(name) != entry["version"]:
            raise Fault("source_identity_mismatch", "inputs.json")
        data = read_bytes(directory, entry["path"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"]:
            raise Fault("source_identity_mismatch", entry["path"])
        response = parse_json(data, entry["path"])
        if not isinstance(response, dict):
            raise Fault("configuration_invalid", entry["path"], 4)
        if (
            index["input_schema"] == "spike_log.dependency-source-inputs.v1"
            and "source_kind" in response
        ):
            raise Fault("configuration_invalid", entry["path"], 4)
        result[name] = digest, response
    return result
