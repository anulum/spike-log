# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Supervise registry capture or complete prepared-source revalidation."""

from __future__ import annotations

import math
import os
import sys
from pathlib import Path

from .inputs import parse_json
from .policy import LEAF_SECONDS
from .processes import run_process
from .reports import Fault, Report, validate_child


def capture(
    root: Path,
    name: str,
    report: Report,
    *,
    budget: float = LEAF_SECONDS,
    artifacts: Path | None = None,
    owner: Path | None = None,
) -> None:
    """Own one complete capture worker and its inclusive execution deadline.

    Parameters
    ----------
    root : Path
        Received repository path, normalized lexically before the supervised worker validates it.
    name : str
        Root-relative snapshot destination supplied only as worker data.
    report : Report
        Receives only an admitted native/report outcome after owned cleanup completes.
    budget : float
        Positive finite inclusive execution/cleanup seconds, at most LEAF_SECONDS.

    artifacts : Path | None
        Explicit local artifact root for prepared-source revalidation.
    owner : Path | None
        Explicit owner tree, passed only as data to the fixed worker.

    Raises
    ------
    Fault
        Raised for invalid budgets, native unavailability/timeout or a contradictory worker report.
    DiagnosticLimit
        Raised when admitted worker findings exhaust the supplied report's diagnostic budget.
    """
    if isinstance(budget, bool) or not math.isfinite(budget) or not 0 < budget <= LEAF_SECONDS:
        raise Fault("configuration_invalid", exit_code=4)
    tools = Path(__file__).resolve().parents[1]
    program = (
        "import sys;sys.path.insert(0," + repr(str(tools)) + ");"
        "from local_scaffold.provenance_capture_worker import main;"
        "raise SystemExit(main(*sys.argv[1:]))"
    )
    result = run_process(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            os.path.abspath(root),
            name,
            os.path.abspath(artifacts) if artifacts is not None else "",
            os.path.abspath(owner) if owner is not None else "",
        ],
        tools.parent,
        budget,
    )
    if result.exit_code not in (0, 2, 3, 4):
        raise Fault("tool_unavailable", exit_code=3)
    child = validate_child(
        parse_json(result.stdout),
        "provenance_reproduction",
        result.exit_code,
        expected_scope="provenance_inputs",
    )
    for reason in child["reasons"]:
        report.observe(Fault(reason["code"], reason["location"], child["exit_code"]))
