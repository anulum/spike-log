# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Inspect native attribution, JSON sidecars and actual licensed source bytes."""

from __future__ import annotations

import hashlib
import math
import os
import sys
import tempfile
import time
from pathlib import Path

from .identity import SPDX_PREFIX, source_header
from .inputs import json_object, read_bytes, read_text
from .inventory import owned_tree
from .policy import ASSETS, LEAF_SECONDS, LICENCE_SHA256, MAX_FILE, PROVENANCE_SHA256
from .processes import ProcessResult, run_process
from .reports import Fault, Report
from .vendored_inputs import is_vendored_wheel, selected_by_provenance

COPYRIGHTS = (
    "SPDX-FileCopyrightText: 1996-2026 Miroslav Šotek <protoscience@anulum.li> (concepts)",
    "SPDX-FileCopyrightText: 2020-2026 Miroslav Šotek <protoscience@anulum.li> (code)",
)


def header_check(name: str, text: str, report: Report) -> None:
    """Validate the native invisible/comment header and reject conflicting SPDX.

    Parameters
    ----------
    name : str
        Maintained lexical filename selecting invisible Markdown/HTML, bare licence or hash-comment ownership syntax.
    text : str
        Original decoded source/notice text; every SPDX declaration is checked for conflict.
    report : Report
        Receives exact ownership/header/SPDX conflicts without rewriting source.
    """
    header = source_header(name)
    if name.endswith((".md", ".html")):
        expected = "<!--\n" + "\n".join(header) + "\n-->"
        if not text.startswith(expected):
            report.add("source_provenance.visible-header", name)
    elif name.endswith(".license"):
        if not text.startswith("\n".join(header) + "\n"):
            report.add("source_provenance.wrong-notice", name)
    else:
        expected = "\n".join("# " + line for line in header)
        if not text.startswith(expected):
            code = (
                "source_provenance.missing-spdx"
                if SPDX_PREFIX not in text[:1000]
                else "source_provenance.wrong-notice"
            )
            report.add(code, name)
    declarations = [
        line.split(SPDX_PREFIX, 1)[1].strip()
        for line in text.splitlines()
        if line.lstrip().startswith(("# " + SPDX_PREFIX, SPDX_PREFIX))
    ]
    if declarations != ["AGPL-3.0-or-later"]:
        report.add("source_provenance.conflicting-spdx", name)


def public_bytes(root: Path, report: Report) -> dict[str, bytes]:
    """Read every bounded owned public input without traversing private caches.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives owned-tree findings; cached and owner-private working documents are outside the public projection.

    Returns
    -------
    dict[str, bytes]
        Every original owned public file's complete bounded bytes keyed by lexical name.

    Raises
    ------
    Fault
        Raised for owned-tree resource/availability or no-follow file read failure.
    """
    return {
        name: read_bytes(root, name, MAX_FILE)
        for name in owned_tree(root, report)
        if not name.startswith("docs/internal/")
    }


def analyse_reuse(root: Path, timeout: float = LEAF_SECONDS) -> ProcessResult:
    """Run unchanged native REUSE on every original public byte under one deadline.

    Original relative names, licences, sidecars and nested policy files are
    retained. A private temporary tree excludes only the already defined cache
    and internal-document scope. Received Git ignores cannot suppress public
    files. The absolute producer runs in isolated mode without executable
    discovery and never imports received code.
    Original and delivered bytes must still agree after the real producer exits.

    Parameters
    ----------
    root : Path
        Repository whose original public bytes are captured into an owned complete REUSE view.
    timeout : float
        Finite positive inclusive budget, at most LEAF_SECONDS; original capture, native REUSE, final identity checks and cleanup share it.

    Returns
    -------
    ProcessResult
        Unmodified native REUSE exit/captures after exact view/original identity verification; received Git configuration/modules are not executed.

    Raises
    ------
    Fault
        Raised for invalid budget, unavailable native producer, changed original/view bytes or exhausted deadline.
    """
    if (
        isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > LEAF_SECONDS
    ):
        raise Fault("configuration_invalid", exit_code=4)
    deadline = time.monotonic() + timeout
    report = Report("source_provenance")
    original = public_bytes(root, report)
    if report.exit_code:
        raise Fault("policy_refusal", exit_code=report.exit_code)
    with tempfile.TemporaryDirectory(prefix="spike-log-reuse-") as temporary:
        directory = Path(temporary)
        for name, data in original.items():
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Fault("tool_timeout", exit_code=3)
        result = run_process(
            [sys.executable, "-I", "-m", "reuse", "--root", str(directory), "lint", "--json"],
            directory,
            remaining,
            environment={
                **os.environ,
                "PATH": os.devnull,
                "GIT_CEILING_DIRECTORIES": str(directory.parent),
            },
        )
        if public_bytes(directory, report) != original or public_bytes(root, report) != original:
            raise Fault("source_identity_mismatch")
        if report.exit_code:
            raise Fault("policy_refusal", exit_code=report.exit_code)
    if time.monotonic() >= deadline:
        raise Fault("tool_timeout", exit_code=3)
    return result


def verify(root: Path, report: Report) -> None:
    """Validate actual source ownership and run the installed REUSE checker.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives owned/third-party licence/header/provenance and actual native REUSE refusals.

    Raises
    ------
    Fault
        Raised for unsafe/unavailable/unbounded input or native process/identity failure.
    """
    files = owned_tree(root, report)
    for name in files:
        if name.startswith("docs/internal/"):
            continue
        try:
            if name in ASSETS:
                if hashlib.sha256(read_bytes(root, name, MAX_FILE)).hexdigest() != ASSETS[name]:
                    report.add("source_provenance.third-party", name)
                continue
            if is_vendored_wheel(name):
                if not selected_by_provenance(root, name):
                    report.add("source_provenance.third-party", name)
                continue
            if name == "LICENSE" or name.startswith("LICENSES/"):
                if name in ("LICENSE", "LICENSES/AGPL-3.0-or-later.txt"):
                    if hashlib.sha256(read_bytes(root, name)).hexdigest() != LICENCE_SHA256:
                        report.add("source_provenance.third-party", name)
                continue
            if name == "src/spike_log/py.typed":
                sidecar_name = name + ".license"
                if read_bytes(root, name) != b"" or sidecar_name not in files:
                    report.add("source_provenance.wrong-notice", name)
                elif any(
                    line not in read_text(root, sidecar_name).splitlines() for line in COPYRIGHTS
                ):
                    report.add("source_provenance.copyright-record", sidecar_name)
                continue
            if name.lower().endswith(".json"):
                value = json_object(root, name)
                sidecar_name = name + ".license"
                if sidecar_name not in files:
                    report.add("source_provenance.json-sidecar", name)
                    continue
                sidecar = read_text(root, sidecar_name)
                if any(line not in sidecar.splitlines() for line in COPYRIGHTS):
                    report.add("source_provenance.copyright-record", sidecar_name)
                for key in ("SPDX-License-Identifier", "spdx_license_identifier"):
                    if key in value and value[key] != "AGPL-3.0-or-later":
                        report.add("source_provenance.conflicting-spdx", name)
                if name == "capability-inventory.json":
                    source = value.get("source_metadata")
                    digest = hashlib.sha256(read_bytes(root, "repository-domain.json")).hexdigest()
                    if source != {"path": "repository-domain.json", "sha256": digest}:
                        report.add("source_provenance.generated-drift", name)
            else:
                header_check(name, read_text(root, name), report)
        except Fault as fault:
            report.observe(fault)
    if (
        hashlib.sha256(read_bytes(root, "dependency-provenance.json")).hexdigest()
        != PROVENANCE_SHA256
    ):
        report.add("source_provenance.third-party", "dependency-provenance.json")
    result = analyse_reuse(root)
    if result.exit_code:
        report.add("source_provenance.reuse-invalid", "REUSE.toml")
