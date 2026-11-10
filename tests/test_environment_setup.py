# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Verify real uv-created producer graphs, hardlinks and fixture isolation."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import SOURCE
from tests.producer_environments import producer_environment
from tests.test_environment_failures import actual_unsupported_python as actual_unsupported_python
from tests.test_environment_failures import genuine_graph_python as genuine_graph_python


def test_full_environment_preserves_graph_and_shared_metadata(genuine_graph_python: Path) -> None:
    """The real Make setup retains all producers while isolating mutable fixture metadata.

    Parameters
    ----------
    genuine_graph_python : Path
        Actual complete graph prepared through the production Make environment target.
    """
    directory = genuine_graph_python.parents[1]
    site = directory / "lib/python3.13/site-packages"
    expected = json.loads((SOURCE / "dependency-provenance.json").read_text())["packages"]
    metadata = sorted(site.glob("*.dist-info/METADATA"))
    assert len(metadata) == len(expected) == 103
    assert all(
        path.stat().st_nlink > 1
        for path in metadata
        if path.parent.name != "packaging-26.3.dist-info"
    )
    mutable = site / "packaging-26.3.dist-info/METADATA"
    retained = directory / "original-packaging-METADATA"
    assert mutable.read_bytes() == retained.read_bytes()
    assert mutable.stat().st_nlink == 1 and retained.stat().st_nlink > 1
    assert mutable.stat().st_ino != retained.stat().st_ino
    observed = subprocess.run(
        [str(genuine_graph_python), "-I", "-c", "import sys;print(sys.prefix)"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert Path(observed.stdout.strip()) == directory
    assert directory != SOURCE / ".venv"


def test_sparse_environment_installs_only_selected_shared_producers(tmp_path: Path) -> None:
    """The shared-cache helper installs the complete selected wheel identities.

    Parameters
    ----------
    tmp_path : Path
        Owned temporary environment location on the cache filesystem.
    """
    records = [
        record
        for record in json.loads((SOURCE / "dependency-provenance.json").read_text())["packages"]
        if record["name"] in ("coverage", "packaging", "pyyaml")
    ]
    wheels = []
    for record in records:
        artifact = record["source_artifact"]
        wheel = SOURCE / ".tool-cache/wheelhouse" / artifact["filename"]
        assert hashlib.sha256(wheel.read_bytes()).hexdigest() == artifact["sha256"]
        wheels.append(wheel)
    python = producer_environment(tmp_path / "environment", wheels)
    result = subprocess.run(
        [
            str(python),
            "-I",
            "-c",
            "import hashlib,importlib.metadata,json,platform;"
            "print(json.dumps({'python':platform.python_version(),'packages':["
            "{'name':d.metadata['Name'].lower(),'version':d.version,"
            "'metadata_sha256':hashlib.sha256(d.read_text('METADATA').encode()).hexdigest()}"
            " for d in importlib.metadata.distributions()]}))",
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    actual = json.loads(result.stdout)
    assert actual["python"] == "3.13.16"
    assert len(actual["packages"]) == 3
    assert {
        record["name"]: (record["version"], record["metadata_sha256"])
        for record in actual["packages"]
    } == {record["name"]: (record["version"], record["metadata_sha256"]) for record in records}
    metadata = list(python.parents[1].glob("lib/python3.13/site-packages/*.dist-info/METADATA"))
    assert len(metadata) == 3 and all(path.stat().st_nlink > 1 for path in metadata)


def test_cold_bootstrap_creates_the_complete_locked_environment(tmp_path: Path) -> None:
    """The real Make entry bootstraps uv before resolving its shared cache.

    Parameters
    ----------
    tmp_path : Path
        Owned clean checkout containing the actual source recipes and lock.
    """
    root = tmp_path / "clean-checkout"
    root.mkdir()
    for name in ("Makefile", "requirements-dev.txt"):
        shutil.copyfile(SOURCE / name, root / name)
    shutil.copytree(SOURCE / ".make", root / ".make")
    bootstrap = root / ".tool-cache/bootstrap-uv"
    bootstrap.mkdir(parents=True)
    os.link(SOURCE / ".tool-cache/bootstrap-uv/uv.whl", bootstrap / "uv.whl")
    assert not (bootstrap / "uv").exists()
    result = subprocess.run(
        ["make", "--no-print-directory", "environment", "BASE_PYTHON=" + sys.executable],
        cwd=root,
        capture_output=True,
        timeout=180,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"Failed to hardlink" not in result.stderr
    assert b"-m pip install" not in result.stdout
    metadata = list((root / ".venv").glob("lib/python3.13/site-packages/*.dist-info/METADATA"))
    assert len(metadata) == 103 and all(path.stat().st_nlink > 1 for path in metadata)
    observed = subprocess.run(
        [
            str(root / ".venv/bin/python"),
            "-I",
            "-c",
            "import hashlib,importlib.metadata,json,re,sys;print(json.dumps({'prefix':sys.prefix,"
            "'packages':{re.sub(r'[-_.]+','-',d.metadata['Name'].lower()):[d.version,"
            "hashlib.sha256(d.read_text('METADATA').encode()).hexdigest()]"
            "for d in importlib.metadata.distributions()}}))",
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    actual = json.loads(observed.stdout)
    expected = {
        record["name"]: [record["version"], record["metadata_sha256"]]
        for record in json.loads((SOURCE / "dependency-provenance.json").read_text())["packages"]
    }
    assert actual["packages"] == expected
    assert Path(actual["prefix"]) == root / ".venv"


@pytest.mark.parametrize(
    ("target", "version"),
    [
        ("prepare-interpreter-fixture", "3.13.15"),
        ("prepare-major-interpreter-fixture", "3.14.7"),
    ],
)
def test_fixture_make_retains_exact_interpreter_and_shared_packages(
    target: str, version: str
) -> None:
    """The real Make fixture target retains its selected interpreter and two producers.

    Parameters
    ----------
    target : str
        Existing exact-interpreter preparation entry point.
    version : str
        Original selected patch version, without a default upgrade.
    """
    result = subprocess.run(
        ["make", "--no-print-directory", target, "BASE_PYTHON=" + sys.executable],
        cwd=SOURCE,
        capture_output=True,
        timeout=180,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert b"Failed to hardlink" not in result.stderr
    environment = (
        SOURCE / ".tool-cache/native-fixtures" / ("cpython-" + version) / "guard-environment-uv"
    )
    metadata = list(environment.glob("lib/python*/site-packages/*.dist-info/METADATA"))
    assert len(metadata) == 2 and all(path.stat().st_nlink > 1 for path in metadata)
    observed = subprocess.run(
        [
            str(environment / "bin/python"),
            "-I",
            "-c",
            "import platform;print(platform.python_version())",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert observed.stdout.strip() == version


def test_original_interpreter_fixture_retains_shared_environment(
    actual_unsupported_python: Path,
) -> None:
    """The original real fixture consumes the selected uv environment unchanged.

    Parameters
    ----------
    actual_unsupported_python : Path
        Original parametrized producer fixture with complete binary and metadata qualification.
    """
    environment = actual_unsupported_python.parents[1]
    assert environment.name == "guard-environment-uv"
    metadata = list(environment.glob("lib/python*/site-packages/*.dist-info/METADATA"))
    assert len(metadata) == 2 and all(path.stat().st_nlink > 1 for path in metadata)
