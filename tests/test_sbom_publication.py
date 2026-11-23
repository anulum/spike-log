# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual SBOM production and protection of unrelated filesystem data."""

import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest

from tests.conftest import SOURCE


@pytest.fixture
def native_sbom_root(root: Path) -> Path:
    """Copy the real admitted CLI launcher, retaining its actual installed interpreter."""
    original = SOURCE / ".venv/bin/cyclonedx-py"
    target = root / ".venv/bin/cyclonedx-py"
    target.parent.mkdir(parents=True)
    shutil.copyfile(original, target)
    target.chmod(0o755)
    assert target.read_bytes() == original.read_bytes()
    return root


def test_make_sbom_records_actual_complete_graph(native_sbom_root: Path) -> None:
    """The public Make target serialises every actual locked producer component."""
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "sbom",
            "PYTHON=" + str(SOURCE / ".venv/bin/python"),
        ],
        cwd=native_sbom_root,
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    value = cast(
        dict[str, object],
        json.loads((native_sbom_root / ".tool-cache/sbom.json").read_bytes()),
    )
    assert value["bomFormat"] == "CycloneDX"
    components = cast(list[dict[str, str]], value["components"])
    actual = {
        entry["name"].lower().replace("_", "-").replace(".", "-"): entry["version"]
        for entry in components
    }
    provenance = cast(
        dict[str, list[dict[str, str]]],
        json.loads((SOURCE / "dependency-provenance.json").read_bytes()),
    )
    expected = {entry["name"]: entry["version"] for entry in provenance["packages"]}
    assert len(components) == len(actual) == len(expected) == 106
    assert actual == expected


@pytest.mark.parametrize("kind", ["cache-parent", "output-file", "dangling-output"])
def test_make_sbom_refuses_symlink_publication(
    native_sbom_root: Path, tmp_path: Path, kind: str
) -> None:
    """Unsafe cache or output links cannot modify or create unrelated owned data."""
    sentinel = b"Original unrelated owned test sentinel.\n"
    outside = tmp_path / "outside-cache"
    outside.mkdir()
    target = outside / "sbom.json"
    if kind != "dangling-output":
        target.write_bytes(sentinel)
    cache = native_sbom_root / ".tool-cache"
    if kind == "cache-parent":
        cache.rename(tmp_path / "preserved-original-cache")
        cache.symlink_to(outside, target_is_directory=True)
    else:
        (cache / "sbom.json").symlink_to(target)
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "sbom",
            "PYTHON=" + str(SOURCE / ".venv/bin/python"),
        ],
        cwd=native_sbom_root,
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 2, (result.stdout, result.stderr)
    if kind == "dangling-output":
        assert not target.exists()
    else:
        assert target.read_bytes() == sentinel
