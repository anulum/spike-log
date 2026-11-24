# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual committed Common source identity and unchanged installed artifacts."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.committed_source import verify_committed_source
from local_scaffold.inputs import Json
from local_scaffold.provenance_reproduction import package_record
from local_scaffold.reports import Fault
from tests.conftest import SOURCE
from tests.test_provenance_local import INPUTS, MANIFEST, OWNER


def original_source() -> tuple[dict[str, Json], dict[str, bytes]]:
    """Read the actual independent committed manifest and every original owner byte."""
    manifest = cast(dict[str, Json], json.loads(MANIFEST.read_bytes()))
    rows = cast(list[dict[str, Json]], manifest["files"])
    files = {cast(str, row["path"]): (OWNER / cast(str, row["path"])).read_bytes() for row in rows}
    for row in rows:
        data = files[cast(str, row["path"])]
        assert len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]
    return manifest, files


def test_actual_committed_source_and_both_complete_local_records() -> None:
    """Prove the real Common commit, then reproduce both original installed wheel records."""
    manifest, files = original_source()
    verify_committed_source(OWNER, manifest, files)
    provenance = json.loads((SOURCE / "dependency-provenance.json").read_text())
    for record in provenance["packages"]:
        if record["name"] not in ("evidence-manifest-toolkit", "rfc8785"):
            continue
        assert record["owner_source"]["state"] == "committed"
        raw = (INPUTS / (record["name"] + ".json")).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert digest == record["source_input_sha256"]
        actual = package_record(
            record, {record["name"]: (digest, json.loads(raw))}, artifacts=INPUTS, owner=OWNER
        )
        assert actual == record


@pytest.mark.parametrize(
    "case",
    (
        "schema",
        "repository",
        "missing-commit",
        "boolean-commit",
        "wrong-commit",
        "wrong-tree",
        "partial-source",
        "changed-source",
        "extra-source",
    ),
)
def test_committed_identity_and_population_disagreements_refuse(case: str) -> None:
    """Adverse changes to original inputs cannot stand in for the actual committed tree."""
    manifest, files = original_source()
    if case == "schema":
        manifest["schema"] = "unverified"
    elif case == "repository":
        manifest["repository"] = "other"
    elif case == "missing-commit":
        del manifest["commit"]
    elif case == "boolean-commit":
        manifest["commit"] = True
    elif case == "wrong-commit":
        manifest["commit"] = "0" * 40
    elif case == "wrong-tree":
        manifest["tree"] = "0" * 40
    elif case == "partial-source":
        del files[next(iter(files))]
    elif case == "changed-source":
        name = next(iter(files))
        files[name] += b"\n"
    else:
        files["untracked-source"] = b"adverse additional source"
    with pytest.raises(Fault) as error:
        verify_committed_source(OWNER, manifest, files)
    assert error.value.exit_code == (
        4 if case in ("schema", "repository", "missing-commit", "boolean-commit") else 2
    )


@pytest.fixture(scope="module")
def copied_owner(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Copy the real complete Git owner once, retaining actual commit objects and source."""
    target = tmp_path_factory.mktemp("committed-owner") / "owner"
    shutil.copytree(
        OWNER,
        target,
        ignore=shutil.ignore_patterns(
            ".venv",
            ".tool-cache",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "internal",
        ),
    )
    return target


@pytest.mark.parametrize("case", ("tracked-change", "untracked-source"))
def test_actual_dirty_owner_refuses_and_recovers(copied_owner: Path, case: str) -> None:
    """Actual native Git status prevents a dirty owner from claiming committed correspondence."""
    manifest, files = original_source()
    name = next(iter(files)) if case == "tracked-change" else "untracked-negative-source"
    target = copied_owner / name
    before = target.read_bytes() if target.exists() else None
    try:
        target.write_bytes((before or b"") + b"\n")
        with pytest.raises(Fault) as error:
            verify_committed_source(copied_owner, manifest, files)
        assert error.value.exit_code == 2
    finally:
        if before is None:
            target.unlink()
        else:
            target.write_bytes(before)
    verify_committed_source(copied_owner, manifest, files)


def test_native_git_does_not_execute_received_fsmonitor(copied_owner: Path) -> None:
    """Received local Git configuration cannot execute its fsmonitor callback."""
    manifest, files = original_source()
    config = copied_owner / ".git/config"
    original = config.read_bytes()
    marker = copied_owner.parent / "fsmonitor-must-not-run"
    script = copied_owner.parent / "fsmonitor"
    script.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
    script.chmod(0o700)
    try:
        subprocess.run(
            ["/usr/bin/git", "-C", str(copied_owner), "config", "core.fsmonitor", str(script)],
            check=True,
        )
        verify_committed_source(copied_owner, manifest, files)
        assert not marker.exists()
    finally:
        config.write_bytes(original)


def test_actual_nongit_owner_refuses(tmp_path: Path) -> None:
    """A real existing directory with no owning Git repository cannot establish a commit.

    Its Git pointer names a directory that does not exist, so Git stops there instead of
    discovering an enclosing checkout, such as the clone that holds the test's tool cache.
    """
    manifest, files = original_source()
    owner = tmp_path / "not-a-git-owner"
    owner.mkdir()
    (owner / ".git").write_text("gitdir: " + str(tmp_path / "absent-git-directory") + "\n")
    with pytest.raises(Fault) as error:
        verify_committed_source(owner, manifest, files)
    assert (error.value.code, error.value.exit_code) == ("source_identity_mismatch", 2)
