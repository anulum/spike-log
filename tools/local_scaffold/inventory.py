# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Verify bounded source trees and publish empty initial inventories exclusively."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import tomllib
from pathlib import Path, PurePosixPath

from .inputs import Json, json_object, read_bytes, relative_path
from .inventory_tracking import verify_tracking as verify_tracking
from .metadata import check
from .package_inventory import verify_package
from .policy import (
    ASSETS,
    EXCLUDED,
    FORBIDDEN,
    MAX_ENTRIES,
    MAX_FILE,
    MAX_PATH,
    MAX_TREE,
    MAX_TREE_DEPTH,
    REPOSITORY,
    REQUIRED,
)
from .production_names import check_file, check_text
from .reports import Fault, Report, safe_location
from .vendored_inputs import is_vendored_wheel, selected_by_provenance


def owned_tree(root: Path, report: Report) -> list[str]:
    """Inspect actual entry kinds and limits without traversing links or caches.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives unsafe name, symbolic/special/wrong-kind entry findings while bounded traversal continues.

    Returns
    -------
    list[str]
        Sorted regular-file names after the fixed directory exclusions. Private working bodies
        are enumerated for kind/budget checks; publication consumers apply their own projection.

    Raises
    ------
    Fault
        Raised when entry/depth/path/file/tree budgets or directory availability fail.
    """
    pending = [root]
    files: list[str] = []
    count, total = 0, 0
    device = root.stat().st_dev
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(directory.iterdir(), key=lambda path: path.name)
        except OSError as error:
            raise Fault("input_unavailable", exit_code=3) from error
        for path in entries:
            name = path.relative_to(root).as_posix()
            count += 1
            if count > MAX_ENTRIES:
                raise Fault("resource_limit")
            if safe_location(name) != name or len(name.encode("utf-8")) > MAX_PATH:
                report.add("policy_refusal")
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                report.add("repository_inventory.symlink-entry", name)
                continue
            if path.name in EXCLUDED:
                if not stat.S_ISDIR(info.st_mode) or info.st_dev != device:
                    report.add("repository_inventory.wrong-kind", name)
                continue
            if not name.startswith("docs/internal/"):
                check_text(name, None, report)
            if len(PurePosixPath(name).parts) > MAX_TREE_DEPTH:
                raise Fault("resource_limit", name)
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                total += info.st_size
                if info.st_size > MAX_FILE or total > MAX_TREE:
                    raise Fault("resource_limit", name)
                files.append(name)
            else:
                report.add("repository_inventory.special-file", name)
    return sorted(files)


def inventory_bytes(root: Path) -> bytes:
    """Construct deterministic empty capability state bound to raw metadata bytes.

    Parameters
    ----------
    root : Path
        Repository supplying exact repository-domain.json bytes for the source metadata digest.

    Returns
    -------
    bytes
        Deterministic newline-terminated JSON declaring local-scaffold/architecture-only maturity and empty capabilities, claims and qualified schema identifiers.

    Raises
    ------
    Fault
        Raised if original metadata bytes cannot be read safely.
    """
    value = {
        "repository_name": REPOSITORY,
        "lifecycle": "public_repository",
        "evidence_maturity": "architecture_only",
        "capabilities": [],
        "claims": [],
        "qualified_owned_schema_ids": [],
        "source_metadata": {
            "path": "repository-domain.json",
            "sha256": hashlib.sha256(read_bytes(root, "repository-domain.json")).hexdigest(),
        },
    }
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def publish(root: Path, output: str, data: bytes) -> None:
    """Publish complete bytes with exclusive linking, fsync and owned-only cleanup.

    A visible complete output survives a later durability fault or interruption.
    Existing destinations are never replaced. Only this invocation's positively
    created sibling temporary file is removed during recovery.

    Parameters
    ----------
    root : Path
        Validated repository root constraining the output's lexical path.
    output : str
        Relative or root-contained absolute destination; traversal and replacement are refused.
    data : bytes
        Complete caller-owned bytes to publish by exclusive hard link after writing and fsync.

    Raises
    ------
    Fault
        Raised for outside/unsafe output, an existing destination or durability/publication failure; positively published bytes are preserved.
    """
    supplied = Path(output)
    if ".." in supplied.parts:
        raise Fault("output_outside_root")
    path = supplied if supplied.is_absolute() else root / supplied
    try:
        name = path.relative_to(root).as_posix()
    except ValueError as error:
        raise Fault("output_outside_root") from error
    path = relative_path(root, name)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".spike-log-inventory-", dir=path.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        temporary = None
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except FileExistsError as error:
        raise Fault("output_exists", name) from error
    except OSError as error:
        raise Fault("output_failure", name) from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def required_paths(root: Path, report: Report) -> None:
    """Check every exact path obligation independently, including regular kind.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives an independent missing/wrong-kind finding for each exact machine-profile path obligation.
    """
    for index, (name, kind) in enumerate(REQUIRED, start=1):
        path = root / name
        if not path.exists() and not path.is_symlink():
            code = (
                f"repository_inventory.missing-path.{index:02d}"
                if index <= 72
                else "input_unavailable"
            )
            report.add(code, name, 3)
        elif path.is_symlink() or (kind == "directory") != path.is_dir():
            report.add("repository_inventory.wrong-kind", name)
        elif kind == "file" and not stat.S_ISREG(path.lstat().st_mode):
            report.add("repository_inventory.special-file", name)


def verify(root: Path, report: Report) -> None:
    """Validate the complete tree and independently verify actual generated state.

    Private working bodies stay outside production naming. Kind, budget and
    actual Git tracking checks still cover their paths.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives metadata, path, naming, tracked-private and exact generated-empty-inventory refusals.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable/unbounded inputs or required native Git failure.
    """
    required_paths(root, report)
    for index, name in enumerate(FORBIDDEN, start=1):
        if (root / name).exists() or (root / name).is_symlink():
            report.add(f"repository_inventory.forbidden-tree.{index:02d}", name)
    files = owned_tree(root, report)
    for name in files:
        if name.startswith("docs/internal/"):
            continue
        if name.endswith((".jpg", ".png")) and name not in ASSETS:
            report.add("repository_inventory.unexpected-binary", name)
        elif is_vendored_wheel(name):
            if not selected_by_provenance(root, name):
                report.add("repository_inventory.unexpected-binary", name)
        elif name not in ASSETS and name != "LICENSE" and not name.startswith("LICENSES/"):
            check_file(root, name, report)
    verify_tracking(root, report)
    config = tomllib.loads(read_bytes(root, "pyproject.toml").decode("utf-8"))
    verify_package(config, files, report)
    check(root, report)
    actual: dict[str, Json] = json_object(root, "capability-inventory.json")
    expected = json.loads(inventory_bytes(root))
    if actual != expected:
        code = (
            "repository_inventory.source-hash"
            if actual.get("source_metadata") != expected["source_metadata"]
            else "repository_inventory.inventory-identity"
        )
        report.add(code, "capability-inventory.json")


def generate(root: Path, report: Report, output: str) -> None:
    """Generate only after real metadata acceptance; no final-tree prerequisite.

    Parameters
    ----------
    root : Path
        Repository whose independent metadata must pass before inventory publication.
    report : Report
        Receives metadata refusals; failing metadata prevents any output publication.
    output : str
        New root-contained exclusive destination; existing files are never rewritten.

    Raises
    ------
    Fault
        Raised for unsafe input, existing/outside output or actual publication/durability failure.
    """
    check(root, report)
    if report.exit_code == 0:
        publish(root, output, inventory_bytes(root))
