# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Acquire genuine pinned artifacts through the public command, the registry and Make.

Every case runs the real public script as a child process over a small copy of the
repository whose dependency provenance selects a few real artifacts. Registry cases need
the network: a missing network is a failure here, never a skip.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from local_scaffold.bootstrap_bindings import MAX_ARTIFACT_BYTES
from local_scaffold.inputs import Json
from tests.conftest import SOURCE, payload, source_python

VENDORED = "vendor/environment-inputs"
WHEEL = VENDORED + "/rfc8785-0.1.4+emt.1-py3-none-any.whl"
REGISTRY = ("rfc3986-validator", "rfc3339-validator")
TRACKED = "rfc8785"
SCRIPT = str(SOURCE / "tools/fetch_environment_inputs.py")


def _packages(*names: str) -> list[dict[str, Json]]:
    """Return deep copies of the repository's own provenance records for the named packages."""
    provenance = cast(
        dict[str, Json], json.loads((SOURCE / "dependency-provenance.json").read_bytes())
    )
    records = {
        cast(str, record["name"]): record
        for record in cast(list[dict[str, Json]], provenance["packages"])
    }
    return [copy.deepcopy(records[name]) for name in names]


def _artifact(package: dict[str, Json]) -> dict[str, Json]:
    """Return one package's selected artifact record."""
    return cast(dict[str, Json], package["source_artifact"])


def _select(root: Path, packages: list[dict[str, Json]]) -> None:
    """Write a dependency provenance that selects exactly these package records."""
    text = json.dumps({"packages": packages}, indent=2, sort_keys=True) + "\n"
    (root / "dependency-provenance.json").write_text(text)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """Copy the actual Makefile, tools and vendored inputs into a genuine Git tree."""
    root = tmp_path / "project"
    shutil.copytree(SOURCE / VENDORED, root / VENDORED)
    shutil.copyfile(SOURCE / "Makefile", root / "Makefile")
    shutil.copytree(SOURCE / ".make", root / ".make")
    shutil.copytree(SOURCE / "tools", root / "tools", ignore=shutil.ignore_patterns("__pycache__"))
    subprocess.run(["git", "init", "--quiet", "-b", "main", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "--", VENDORED], check=True)
    _select(root, _packages(*REGISTRY, TRACKED))
    return root


def fetch(root: Path, destination: Path, *extra: str) -> subprocess.CompletedProcess[bytes]:
    """Run the real public script with explicit selections and a JSON report."""
    return subprocess.run(
        source_python(
            SCRIPT, "--root", str(root), "--artifacts", str(destination), "--json", *extra
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=180,
    )


def codes(result: subprocess.CompletedProcess[bytes], expected: int) -> list[str]:
    """Return the report's reason codes after checking the native exit and wire shape."""
    report = payload(result, expected)
    assert report["gate"] == "environment_input_fetch"
    return [cast(str, reason["code"]) for reason in cast(list[dict[str, Json]], report["reasons"])]


def _contents(directory: Path) -> dict[str, tuple[int, str]]:
    """Return every entry's length and digest."""
    return {
        path.name: (len(path.read_bytes()), hashlib.sha256(path.read_bytes()).hexdigest())
        for path in directory.iterdir()
    }


def _pins(packages: list[dict[str, Json]]) -> dict[str, tuple[int, str]]:
    """Return the pinned length and digest of each selected artifact."""
    return {
        cast(str, _artifact(p)["filename"]): (
            cast(int, _artifact(p)["bytes"]),
            cast(str, _artifact(p)["sha256"]),
        )
        for p in packages
    }


def _expected(packages: list[dict[str, Json]]) -> dict[str, tuple[int, str]]:
    """Return every acquired file's length and digest.

    Parameters
    ----------
    packages : list of dict
        Selected provenance records.

    Returns
    -------
    dict
        The selected artifacts, then each local package's response record and the records it
        references, by flat name.
    """
    expected = _pins(packages)
    for package in packages:
        if "source_kind" in package:
            record = SOURCE / VENDORED / (cast(str, package["name"]) + ".json")
            data = record.read_bytes()
            expected[record.name] = (len(data), hashlib.sha256(data).hexdigest())
            value = cast(dict[str, Json], json.loads(data))
            for reference in [value["owner_manifest"], *cast(list[Json], value["build_inputs"])]:
                entry = cast(dict[str, Json], reference)
                expected[cast(str, entry["path"])] = (
                    cast(int, entry["bytes"]),
                    cast(str, entry["sha256"]),
                )
    return expected


def test_selected_artifacts_are_acquired_from_their_pinned_origins(
    project: Path, tmp_path: Path
) -> None:
    """Two registry wheels, the vendored wheel and its records arrive whole, alone and verified."""
    destination = tmp_path / "inputs"
    assert codes(fetch(project, destination), 0) == []
    assert _contents(destination) == _expected(_packages(*REGISTRY, TRACKED))


def test_make_target_acquires_into_the_selected_directory(project: Path, tmp_path: Path) -> None:
    """The Make target runs the same command under the selected base interpreter."""
    destination = tmp_path / "make-inputs"
    result = subprocess.run(
        [
            "make",
            "--no-print-directory",
            "fetch-environment-inputs",
            "BASE_PYTHON=" + sys.executable,
            "ENVIRONMENT_INPUTS=" + str(destination),
        ],
        cwd=project,
        capture_output=True,
        timeout=180,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert json.loads(result.stdout.splitlines()[-1])["status"] == "passed"
    assert _contents(destination) == _expected(_packages(*REGISTRY, TRACKED))


def test_text_report_names_the_gate_and_status(project: Path, tmp_path: Path) -> None:
    """Without --json the command writes its fixed readable status line."""
    _select(project, _packages(TRACKED))
    destination = tmp_path / "inputs"
    result = subprocess.run(
        source_python(SCRIPT, "--root", str(project), "--artifacts", str(destination)),
        cwd=SOURCE,
        capture_output=True,
        timeout=60,
    )
    assert (result.returncode, result.stdout, result.stderr) == (
        0,
        b"environment_input_fetch: passed (local_scaffold)\n",
        b"",
    )
    assert _contents(destination) == _expected(_packages(TRACKED))


def test_existing_destination_is_refused_unchanged(project: Path, tmp_path: Path) -> None:
    """An existing destination is never written into."""
    destination = tmp_path / "inputs"
    destination.mkdir()
    (destination / "kept").write_bytes(b"kept\n")
    assert codes(fetch(project, destination), 2) == ["output_exists"]
    assert _contents(destination) == {"kept": (5, hashlib.sha256(b"kept\n").hexdigest())}


def test_missing_or_linked_parent_is_refused(project: Path, tmp_path: Path) -> None:
    """The destination's parent must exist and no ancestor may be a symbolic link."""
    assert codes(fetch(project, tmp_path / "absent" / "inputs"), 3) == ["root_unavailable"]
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    assert codes(fetch(project, tmp_path / "link" / "inputs"), 2) == ["root_symlink"]
    assert not (tmp_path / "absent").exists() and list((tmp_path / "real").iterdir()) == []


def test_unwritable_parent_is_an_output_failure(project: Path, tmp_path: Path) -> None:
    """A parent that refuses the new directory gives output_failure and no directory."""
    parent = tmp_path / "read-only"
    parent.mkdir()
    parent.chmod(0o500)
    try:
        assert codes(fetch(project, parent / "inputs"), 2) == ["output_failure"]
    finally:
        parent.chmod(0o700)
    assert list(parent.iterdir()) == []


def test_write_failure_removes_the_created_directory(project: Path, tmp_path: Path) -> None:
    """A name whose temporary file cannot be created fails the write and leaves nothing."""
    packages = _packages(TRACKED)
    name = "r" * 250 + ".whl"
    shutil.copyfile(project / WHEEL, project / VENDORED / name)
    subprocess.run(["git", "-C", str(project), "add", "--", VENDORED + "/" + name], check=True)
    _artifact(packages[0])["filename"] = name
    _select(project, packages)
    destination = tmp_path / "inputs"
    assert codes(fetch(project, destination), 2) == ["output_failure"]
    assert not destination.exists()


@pytest.mark.parametrize(
    "extra",
    [
        ["--timeout", "0"],
        ["--timeout", "-1"],
        ["--timeout", "nan"],
        ["--timeout", "inf"],
        ["--timeout", "301"],
        ["--timeout", "soon"],
        ["--artifacts", ""],
        ["--unknown"],
    ],
)
def test_invalid_invocations_create_nothing(
    project: Path, tmp_path: Path, extra: list[str]
) -> None:
    """Invalid selections are refused as invocations, without echoing their values."""
    destination = tmp_path / "inputs"
    result = fetch(project, destination, *extra)
    assert codes(result, 4) == ["configuration_invalid"]
    assert not destination.exists() and b"soon" not in result.stdout


def test_missing_artifacts_selection_is_invalid(project: Path) -> None:
    """The destination is an explicit selection with no default."""
    result = subprocess.run(
        source_python(SCRIPT, "--root", str(project), "--json"),
        cwd=SOURCE,
        capture_output=True,
        timeout=60,
    )
    assert codes(result, 4) == ["configuration_invalid"]


def test_missing_provenance_is_unavailable(project: Path, tmp_path: Path) -> None:
    """Without the provenance there is nothing to select."""
    (project / "dependency-provenance.json").unlink()
    assert codes(fetch(project, tmp_path / "inputs"), 3) == ["input_unavailable"]


PINNED_URL = cast(str, _artifact(_packages(REGISTRY[0])[0])["url"])
PINNED_PATH = PINNED_URL.removeprefix("https://files.pythonhosted.org")


@pytest.mark.parametrize(
    ("target", "key", "value"),
    [
        (0, "url", "http://files.pythonhosted.org" + PINNED_PATH),
        (0, "url", "https://127.0.0.1:{port}" + PINNED_PATH),
        (0, "url", "https://user@files.pythonhosted.org" + PINNED_PATH),
        (0, "url", "https://files.pythonhosted.org:443" + PINNED_PATH),
        (0, "url", PINNED_URL + "?mirror=1"),
        (0, "url", PINNED_URL + "#fragment"),
        (0, "url", PINNED_URL.replace("rfc3986_validator-0.1.1", "rfc3986_validator-0.1.2")),
        (0, "url", None),
        (0, "path", WHEEL),
        (0, "kind", "egg"),
        (0, "kind", ["bdist_wheel"]),
        (0, "filename", "../rfc3986_validator-0.1.1-py2.py3-none-any.whl"),
        (0, "bytes", 0),
        (0, "bytes", MAX_ARTIFACT_BYTES + 1),
        (0, "bytes", True),
        (0, "sha256", "2F235C432EF459970B4306369336B9D5DBDDA31B510CA1E327636E01F528BFA9"),
        (2, "url", PINNED_URL),
        (2, "path", "../" + WHEEL),
    ],
)
def test_refused_origins_make_no_connection_and_no_directory(
    project: Path, tmp_path: Path, target: int, key: str, value: Json
) -> None:
    """Every origin outside the fixed rules is refused before any connection or write."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        packages = _packages(*REGISTRY, TRACKED)
        selected = value.replace("{port}", str(port)) if isinstance(value, str) else value
        _artifact(packages[target])[key] = selected
        _select(project, packages)
        destination = tmp_path / "inputs"
        assert codes(fetch(project, destination), 2) == ["policy_refusal"]
        listener.setblocking(False)
        with pytest.raises(BlockingIOError):
            listener.accept()
    assert not destination.exists()


@pytest.mark.parametrize(
    "packages",
    [
        {"packages": []},
        {"packages": {"rfc8785": None}},
        {"packages": ["rfc8785"]},
        {"packages": [{"source_artifact": "rfc8785"}]},
    ],
)
def test_malformed_provenance_is_refused(
    project: Path, tmp_path: Path, packages: dict[str, Json]
) -> None:
    """A provenance without a nonempty list of artifact records selects nothing."""
    (project / "dependency-provenance.json").write_text(json.dumps(packages))
    assert codes(fetch(project, tmp_path / "inputs"), 2) == ["policy_refusal"]
    assert not (tmp_path / "inputs").exists()


def test_repeated_destination_name_is_refused(project: Path, tmp_path: Path) -> None:
    """Two records may not publish the same flat name."""
    _select(project, _packages(TRACKED, TRACKED))
    assert codes(fetch(project, tmp_path / "inputs"), 2) == ["duplicate_member"]
    assert not (tmp_path / "inputs").exists()


def test_untracked_or_linked_vendored_wheel_is_refused(project: Path, tmp_path: Path) -> None:
    """The vendored wheel must be a tracked regular file at its exact path."""
    _select(project, _packages(TRACKED))
    subprocess.run(["git", "-C", str(project), "rm", "--cached", "-q", "--", WHEEL], check=True)
    assert codes(fetch(project, tmp_path / "inputs"), 2) == ["policy_refusal"]
    held = project / "held.whl"
    (project / WHEEL).rename(held)
    (project / WHEEL).symlink_to(held)
    subprocess.run(["git", "-C", str(project), "add", "--", WHEEL], check=True)
    assert codes(fetch(project, tmp_path / "inputs"), 2) == ["repository_inventory.symlink-entry"]
    assert not (tmp_path / "inputs").exists()


def test_vendored_wheel_identity_is_checked_before_any_directory(
    project: Path, tmp_path: Path
) -> None:
    """A tracked file of another length is refused before the destination exists."""
    packages = _packages(*REGISTRY, TRACKED)
    _artifact(packages[2])["bytes"] = 23460
    _select(project, packages)
    assert codes(fetch(project, tmp_path / "inputs"), 2) == ["source_identity_mismatch"]
    assert not (tmp_path / "inputs").exists()


def test_local_packages_share_their_owner_manifest_once(project: Path, tmp_path: Path) -> None:
    """Both local packages reference one owner manifest, which is acquired once."""
    packages = _packages("evidence-manifest-toolkit", TRACKED)
    _select(project, packages)
    destination = tmp_path / "inputs"
    assert codes(fetch(project, destination), 0) == []
    assert _contents(destination) == _expected(packages)
    assert "owner-source-inputs.json" in _contents(destination)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("response-bytes", "source_identity_mismatch"),
        ("reference-bytes", "source_identity_mismatch"),
        ("reference-keys", "policy_refusal"),
        ("reference-name", "policy_refusal"),
        ("references-shape", "policy_refusal"),
        ("pin-missing", "policy_refusal"),
        ("package-name", "policy_refusal"),
        ("shared-name", "duplicate_member"),
    ],
)
def test_vendored_records_are_bound_before_any_directory(
    project: Path, tmp_path: Path, change: str, code: str
) -> None:
    """Each record is admitted only under the pin of the record that names it.

    Parameters
    ----------
    project : Path
        Genuine copy whose vendored inputs and provenance agree.
    tmp_path : Path
        Owned parent of the destination that must stay absent.
    change : str
        The response record's bytes, a referenced record's bytes, a reference's keys or name,
        the reference list's shape, the missing pin, an unsafe package name, or a shared record
        name under other bytes.
    code : str
        The refusal the change must produce.
    """
    packages = _packages("evidence-manifest-toolkit", TRACKED)
    local = packages[1]
    record = project / VENDORED / "rfc8785.json"
    if change == "reference-bytes":
        referenced = project / VENDORED / "rfc8785-source-provenance.json"
        referenced.write_bytes(referenced.read_bytes() + b"\n")
    elif change == "pin-missing":
        del local["source_input_sha256"]
    elif change == "package-name":
        local["name"] = "../rfc8785"
    elif change != "response-bytes":
        value = cast(dict[str, Json], json.loads(record.read_bytes()))
        manifest = cast(dict[str, Json], value["owner_manifest"])
        if change == "reference-keys":
            value["owner_manifest"] = {"path": manifest["path"]}
        elif change == "reference-name":
            manifest["path"] = "../owner-source-inputs.json"
        elif change == "references-shape":
            value["build_inputs"] = "rfc8785-source-provenance.json"
        else:
            manifest["sha256"] = "0" * 64
        record.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    if change == "response-bytes":
        record.write_bytes(record.read_bytes() + b"\n")
    elif change not in ("pin-missing", "package-name", "reference-bytes"):
        local["source_input_sha256"] = hashlib.sha256(record.read_bytes()).hexdigest()
    _select(project, packages)
    assert codes(fetch(project, tmp_path / "inputs"), 2) == [code]
    assert not (tmp_path / "inputs").exists()


def test_absent_registry_path_is_unavailable(project: Path, tmp_path: Path) -> None:
    """A status other than 200 is never followed and leaves no directory."""
    packages = _packages(REGISTRY[1])
    name = cast(str, _artifact(packages[0])["filename"])
    _artifact(packages[0])["url"] = (
        "https://files.pythonhosted.org/packages/00/00/" + "0" * 60 + "/" + name
    )
    _select(project, packages)
    assert codes(fetch(project, tmp_path / "inputs"), 3) == ["input_unavailable"]
    assert not (tmp_path / "inputs").exists()


def test_declared_length_other_than_the_pin_is_refused(project: Path, tmp_path: Path) -> None:
    """The registry's declared length must equal the pin before any body byte is kept."""
    packages = _packages(REGISTRY[1])
    _artifact(packages[0])["bytes"] = cast(int, _artifact(packages[0])["bytes"]) - 1
    _select(project, packages)
    assert codes(fetch(project, tmp_path / "inputs"), 2) == ["source_identity_mismatch"]
    assert not (tmp_path / "inputs").exists()


def test_other_bytes_remove_every_artifact_already_written(project: Path, tmp_path: Path) -> None:
    """A digest mismatch after a verified artifact leaves neither of them."""
    packages = _packages(*REGISTRY)
    digest = cast(str, _artifact(packages[1])["sha256"])
    _artifact(packages[1])["sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
    _select(project, packages)
    assert codes(fetch(project, tmp_path / "inputs"), 2) == ["source_identity_mismatch"]
    assert not (tmp_path / "inputs").exists()


def test_connection_timeout_is_unavailable(project: Path, tmp_path: Path) -> None:
    """A connection that cannot complete within the timeout is unavailable, not refused."""
    _select(project, _packages(REGISTRY[1]))
    assert codes(fetch(project, tmp_path / "inputs", "--timeout", "0.000001"), 3) == [
        "input_unavailable"
    ]
    assert not (tmp_path / "inputs").exists()


def test_acquisition_writes_only_the_destination(project: Path, tmp_path: Path) -> None:
    """The repository copy is unchanged by an acquisition."""
    before = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in project.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }
    assert codes(fetch(project, tmp_path / "inputs"), 0) == []
    after = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in project.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }
    assert after == before
    assert sorted(os.listdir(tmp_path)) == ["inputs", "project"]


def test_public_function_returns_the_native_exit(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The script's main function acquires in process and returns the same native exit."""
    from fetch_environment_inputs import main

    _select(project, _packages(TRACKED))
    destination = tmp_path / "inputs"
    arguments = ["--root", str(project), "--artifacts", str(destination), "--json"]
    assert main(arguments) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "passed"
    assert _contents(destination) == _expected(_packages(TRACKED))
    assert main(arguments) == 2
    assert json.loads(capsys.readouterr().out)["reasons"][0]["code"] == "output_exists"
