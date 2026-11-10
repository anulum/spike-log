# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Run explicit source capture and offline provenance generation/comparison."""

from __future__ import annotations

import signal
import sys
from pathlib import Path

from .cli import SafeParser, SingleInput, interrupted, retain_fault
from .inputs import root_directory
from .policy import LEAF_SECONDS
from .reports import DiagnosticLimit, Fault, Report


def main(arguments: list[str] | None = None) -> int:
    """Run explicit source capture, prospective generation or read-only comparison.

    Parameters
    ----------
    arguments : list[str] | None
        Explicit command tokens, or process argv when None.

    Returns
    -------
    int
        Exit 0 for the requested operation, 2 for refusal, 3 for unavailable or interrupted work,
        or 4 for invalid invocation/configuration; this result is not trusted audit admission.
    """
    tokens = list(sys.argv[1:] if arguments is None else arguments)
    report = Report("provenance_reproduction")
    parser = SafeParser(
        description="Capture source bytes or reconstruct dependency provenance offline.",
        allow_abbrev=False,
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--inputs", action=SingleInput, required=True)
    parser.add_argument("--mode", choices=["capture", "generate", "verify"], default="verify")
    parser.add_argument("--output", action=SingleInput)
    parser.add_argument("--reference", action=SingleInput)
    parser.add_argument("--capture-seconds", action=SingleInput)
    parser.add_argument("--artifacts", action=SingleInput)
    parser.add_argument("--owner-source", action=SingleInput)
    parser.add_argument("--json", action="store_true")
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        options = parser.parse_args(tokens)
        if (
            (options.mode == "generate") != bool(options.output)
            or (options.mode != "verify" and options.reference is not None)
            or (options.mode != "capture" and options.capture_seconds is not None)
        ):
            raise Fault("invocation_invalid", exit_code=4)
        artifacts = (
            root_directory(str(options.artifacts)) if options.artifacts is not None else None
        )
        owner = (
            root_directory(str(options.owner_source)) if options.owner_source is not None else None
        )
        if options.mode == "capture":
            from .provenance_capture import capture

            report.scope = "provenance_inputs"
            try:
                budget = (
                    LEAF_SECONDS
                    if options.capture_seconds is None
                    else float(options.capture_seconds)
                )
            except ValueError as error:
                raise Fault("invocation_invalid", exit_code=4) from error
            capture(
                Path(str(options.root)),
                str(options.inputs),
                report,
                budget=budget,
                artifacts=artifacts,
                owner=owner,
            )
        else:
            from .provenance_reproduction import reproduce

            report.scope = (
                "provenance_candidate" if options.mode == "generate" else "provenance_comparison"
            )
            reproduce(
                root_directory(str(options.root)),
                root_directory(str(options.inputs)),
                report,
                output=options.output,
                reference=options.reference or "dependency-provenance.json",
                artifacts=artifacts,
                owner=owner,
            )
    except Fault as fault:
        retain_fault(report, fault)
    except DiagnosticLimit:
        pass
    except (ImportError, ModuleNotFoundError):
        retain_fault(report, Fault("tool_unavailable", exit_code=3))
    except KeyboardInterrupt:
        retain_fault(report, Fault("interrupted", exit_code=3))
    except Exception:
        retain_fault(report, Fault("unexpected_fault"))
    finally:
        signal.signal(signal.SIGTERM, previous)
    return report.emit("--json" in tokens)
