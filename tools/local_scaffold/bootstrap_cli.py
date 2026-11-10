# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — environment input command

"""Expose only read-only bootstrap input verification through fixed arguments."""

from __future__ import annotations

import argparse
import sys
from typing import Never

from .bootstrap_inputs import verify
from .inputs import root_directory
from .limits import MAX_TREE
from .reports import Exit, Fault, Report


class _Arguments(argparse.Namespace):
    """Retain only the explicit operator data selections."""

    root: str
    artifacts: str
    owner_source: str
    environment: str
    max_input_bytes: int
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
    """Verify every bootstrap operand without creating runtime state.

    Parameters
    ----------
    arguments : list[str] | None
        Explicit command tokens, or native process arguments.

    Returns
    -------
    int
        Closed native0/2/3/4 input-readiness result; no full admission follows.
    """
    report = Report("environment_inputs")
    json_mode = "--json" in (sys.argv[1:] if arguments is None else arguments)
    parser = _Parser(add_help=False, allow_abbrev=False)
    parser.add_argument("--root", default=".")
    parser.add_argument("--artifacts", required=True)
    parser.add_argument("--owner-source", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--max-input-bytes", type=int, default=MAX_TREE)
    parser.add_argument("--json", action="store_true")
    parsed = _Arguments()
    try:
        parser.parse_args(arguments, namespace=parsed)
        if not parsed.artifacts or not parsed.owner_source:
            raise Fault("input_unavailable", "environment-inputs", 3)
        verify(
            root_directory(parsed.root),
            root_directory(parsed.artifacts),
            root_directory(parsed.owner_source),
            parsed.environment,
            max_input_bytes=parsed.max_input_bytes,
        )
    except Fault as fault:
        report.observe(fault)
    except OSError:
        report.observe(Fault("input_unavailable", "environment", 3))
    return report.emit(json_mode)
