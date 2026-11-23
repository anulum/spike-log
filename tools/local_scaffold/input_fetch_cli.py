# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Expose only the pinned environment input acquisition through fixed arguments."""

from __future__ import annotations

import argparse
import math
import sys
from typing import Final, Never

from .input_fetch import acquire
from .inputs import root_directory
from .reports import Exit, Fault, Report

MAX_TIMEOUT_SECONDS: Final = 300.0


class _Arguments(argparse.Namespace):
    """Retain only the explicit operator selections."""

    root: str
    artifacts: str
    timeout: float
    json: bool


class _Parser(argparse.ArgumentParser):
    """Refuse invalid tokens without echoing received values."""

    def error(self, message: str) -> Never:
        """Replace native received-value diagnostics with a fixed refusal.

        Parameters
        ----------
        message : str
            Native diagnostic deliberately not reflected.

        Raises
        ------
        Fault
            Always raised as an invalid invocation.
        """
        raise Fault("configuration_invalid", exit_code=4)


def main(arguments: list[str] | None = None) -> Exit:
    """Acquire every selected environment artifact into a new directory.

    Parameters
    ----------
    arguments : list[str] | None
        Explicit command tokens, or native process arguments.

    Returns
    -------
    int
        Closed native 0/2/3/4 result: 0 when every artifact was acquired and verified,
        2 for a refusal, 3 for an unavailable root, registry or file, 4 for an invalid
        invocation. Acquisition is not an environment, security or publication admission.
    """
    report = Report("environment_input_fetch")
    json_mode = "--json" in (sys.argv[1:] if arguments is None else arguments)
    parser = _Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("--root", default=".")
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--json", action="store_true")
    parsed = _Arguments()
    try:
        parser.parse_args(arguments, namespace=parsed)
        if not (
            parsed.artifacts
            and math.isfinite(parsed.timeout)
            and 0 < parsed.timeout <= MAX_TIMEOUT_SECONDS
        ):
            raise Fault("configuration_invalid", exit_code=4)
        acquire(root_directory(parsed.root), parsed.artifacts, parsed.timeout)
    except Fault as fault:
        report.observe(fault)
    return report.emit(json_mode)
