# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance
"""Keep the vendored environment inputs public-safe and bound to each other and the locks."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, payload, run_guard

VENDORED = SOURCE / "vendor/environment-inputs"
PRIVATE = re.compile(r"/media/|/home/|/mnt/|/tmp/|/Users/|\.coordination|[A-Za-z]:\\")
"""A workstation, temporary or coordination location that a public record must not name."""


def _strings(value: Json) -> list[str]:
    """Return every string in a parsed JSON value, keys included.

    Parameters
    ----------
    value : Json
        Parsed record content.

    Returns
    -------
    list of str
        Each key and string value, depth first.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in (key, *_strings(item))]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    return []


def private_locations(directory: Path) -> dict[str, list[str]]:
    """Return, per record, every string naming a private or absolute location.

    Parameters
    ----------
    directory : Path
        Directory of vendored JSON records.

    Returns
    -------
    dict
        Record name to its offending strings; empty when every record is public-safe.
    """
    found: dict[str, list[str]] = {}
    for record in sorted(directory.glob("*.json")):
        texts = _strings(cast(Json, json.loads(record.read_bytes())))
        found[record.name] = [
            text for text in texts if PRIVATE.search(text) or text.startswith("/")
        ]
    return {name: bad for name, bad in found.items() if bad}


def test_vendored_records_name_no_private_location() -> None:
    """No vendored record names an absolute, home, temporary or coordination location."""
    assert sorted(path.name for path in VENDORED.glob("*.json"))
    assert private_locations(VENDORED) == {}


def test_every_record_reference_resolves_to_its_vendored_file() -> None:
    """Each wheel, manifest and build input a response record names is vendored with that identity."""
    for response in ("evidence-manifest-toolkit.json", "rfc8785.json"):
        value = cast(dict[str, Json], json.loads((VENDORED / response).read_bytes()))
        references = [
            value["wheel"],
            value["owner_manifest"],
            *cast(list[Json], value["build_inputs"]),
        ]
        for reference in references:
            entry = cast(dict[str, Json], reference)
            data = (VENDORED / cast(str, entry["path"])).read_bytes()
            assert (len(data), hashlib.sha256(data).hexdigest()) == (
                entry["bytes"],
                entry["sha256"],
            )


def test_locks_and_provenance_pin_the_vendored_wheels() -> None:
    """Both locks and the dependency provenance select exactly the vendored wheel bytes."""
    provenance = cast(
        dict[str, Json], json.loads((SOURCE / "dependency-provenance.json").read_bytes())
    )
    packages = cast(list[dict[str, Json]], provenance["packages"])
    for name, filename in (
        ("evidence-manifest-toolkit", "evidence_manifest_toolkit-0.0.0.dev0-py3-none-any.whl"),
        ("rfc8785", "rfc8785-0.1.4+emt.1-py3-none-any.whl"),
    ):
        digest = hashlib.sha256((VENDORED / filename).read_bytes()).hexdigest()
        artifact = cast(
            dict[str, Json], next(p for p in packages if p["name"] == name)["source_artifact"]
        )
        assert (artifact["filename"], artifact["sha256"]) == (filename, digest)
        for lock in ("requirements-dev.txt", "requirements-runtime.txt"):
            assert "--hash=sha256:" + digest in (SOURCE / lock).read_text(encoding="utf-8")
    lock_digest = hashlib.sha256((SOURCE / "requirements-dev.txt").read_bytes()).hexdigest()
    assert provenance["lock_sha256"] == lock_digest


@pytest.mark.parametrize(
    ("gate", "case", "code"),
    [
        ("repository_inventory", "changed", "repository_inventory.unexpected-binary"),
        ("repository_inventory", "unselected", "repository_inventory.unexpected-binary"),
        ("source_provenance", "changed", "source_provenance.third-party"),
    ],
)
def test_gates_refuse_a_vendored_wheel_the_provenance_does_not_select(
    root: Path, gate: str, case: str, code: str
) -> None:
    """A vendored wheel is admitted only with the exact bytes the provenance selects.

    Parameters
    ----------
    root : Path
        Genuine isolated copy of the repository, whose selected vendored wheels pass.
    gate : str
        Public guard that classifies the vendored wheel.
    case : str
        A selected wheel with one byte appended, or a wheel the provenance does not select.
    code : str
        The guard's refusal for that wheel.
    """
    name = (
        "rfc8785-0.1.4+emt.1-py3-none-any.whl"
        if case == "changed"
        else "unselected-0.0.0-py3-none-any.whl"
    )
    wheel = root / "vendor/environment-inputs" / name
    wheel.write_bytes((wheel.read_bytes() if case == "changed" else b"PK") + b"\0")
    reasons = cast(list[dict[str, Json]], payload(run_guard(gate, root), 2)["reasons"])
    assert (code, "vendor/environment-inputs/" + name) in [
        (reason["code"], reason["location"]) for reason in reasons
    ]
