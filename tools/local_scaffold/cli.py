# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Public fixed guard dispatch with safe invocation and report-write failures."""

from __future__ import annotations

import argparse
import signal
import sys
from types import FrameType
from typing import NoReturn

from .inputs import root_directory
from .policy import ROLES
from .reports import DiagnosticLimit, Fault, Report


class SafeParser(argparse.ArgumentParser):
    """Replace parser exceptions containing caller input with one authored error."""

    def error(self, message: str) -> NoReturn:
        """Refuse invocation without reflecting untrusted option or value strings.

        Parameters
        ----------
        message : str
            ArgumentParser's received error text, deliberately discarded instead of reflected.

        Raises
        ------
        Fault
            Always raised as invocation_invalid with exit 4.
        """
        raise Fault("invocation_invalid", exit_code=4)


class SingleInput(argparse.Action):
    """Admit one nonempty option value, including the equivalent equals spelling."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        """Refuse empty or repeated inputs without reflecting their values.

        Parameters
        ----------
        parser : argparse.ArgumentParser
            Owning native argument parser; not used to emit received strings.
        namespace : argparse.Namespace
            Native destination namespace updated only for the first nonempty input.
        values : object
            Received input value; empty or repeated destinations are refused without reflecting contents.
        option_string : str | None
            Native option spelling, unused for acceptance or error text.

        Raises
        ------
        Fault
            Raised as invocation_invalid with exit4 for an empty or repeated input.
        """
        if not values or getattr(namespace, self.dest) is not None:
            raise Fault("invocation_invalid", exit_code=4)
        setattr(namespace, self.dest, values)


def interrupted(signum: int, frame: FrameType | None) -> NoReturn:
    """Convert an actual termination signal into owned-resource recovery.

    Parameters
    ----------
    signum : int
        Native termination signal number; its received value is not emitted.
    frame : FrameType | None
        Python frame supplied by signal handling, unused for input discovery.

    Raises
    ------
    KeyboardInterrupt
        Always raised so the owning guard executes its cleanup path.
    """
    raise KeyboardInterrupt


def retain_fault(report: Report, fault: Fault) -> None:
    """Preserve a terminal fault even when the finite diagnostic budget is full.

    Parameters
    ----------
    report : Report
        Receives the authored fault under native exit precedence and the finite reason budget.
    fault : Fault
        Authored code, optional safe location and native exit to retain.
    """
    try:
        report.observe(fault)
    except DiagnosticLimit:
        pass


def main(gate: str, arguments: list[str] | None = None) -> int:
    """Run one fixed public operation and emit its exact bounded scoped report.

    Parameters
    ----------
    gate : str
        Fixed public guard identity; selects one implemented operation, never a received command.
    arguments : list[str] | None
        Explicit CLI tokens, or process argv when None. Unknown/invalid options are refused;
        SingleInput options and repeated audit-production requests have separate duplicate checks.

    Returns
    -------
    int
        Exit 0 for the requested operation, 2 for refusal/output failure, 3 for unavailability/interruption, or 4 for invalid invocation/configuration.
    """
    arguments = list(sys.argv[1:] if arguments is None else arguments)
    report = Report(gate)
    json_mode = "--json" in arguments
    parser = SafeParser(description="Validate local repository infrastructure.", allow_abbrev=False)
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    if gate == "workflow_policy":
        parser.add_argument(
            "--outcomes",
            action=SingleInput,
            metavar="ROOT_RELATIVE_JSON_FILE",
            help="also require all six caller-supplied workflow outcomes to be success",
        )
    if gate == "dependency_alignment":
        parser.add_argument("--produce-audit", action="store_true")
    if gate == "repository_inventory":
        parser.add_argument("--mode", choices=["verify", "generate"], default="verify")
        parser.add_argument("--output")
    if gate == "preflight":
        parser.add_argument("--profile", choices=["local-scaffold"], default="local-scaffold")
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        options = parser.parse_args(arguments)
        if gate == "dependency_alignment" and arguments.count("--produce-audit") > 1:
            raise Fault("invocation_invalid", exit_code=4)
        if gate == "repository_inventory":
            if (options.mode == "generate") != bool(options.output):
                raise Fault("invocation_invalid", exit_code=4)
            if options.mode == "generate":
                report.scope = "inventory_generate"
        root = root_directory(str(options.root))
        if gate == "repository_metadata":
            from .metadata import verify
        elif gate == "source_provenance":
            from .provenance import verify
        elif gate == "workflow_policy":
            from .workflows import verify
        elif gate == "dependency_alignment":
            if options.produce_audit:
                from .audit_producer import produce

                report.scope = "audit_produce"
                produce(root, report)
                return report.emit(json_mode)
            from .dependencies import verify
        elif gate == "documentation":
            from .documentation import verify
        elif gate == "repository_inventory":
            from .inventory import generate, verify

            if options.mode == "generate":
                generate(root, report, str(options.output))
                return report.emit(json_mode)
        elif gate == "preflight":
            from .orchestration import verify
        else:
            raise Fault("configuration_invalid", exit_code=4)
        verify(root, report)
        if gate == "workflow_policy" and options.outcomes is not None:
            from .workflows import verify_outcomes

            verify_outcomes(root, str(options.outcomes), report)
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
    if gate == "preflight":
        observed = {check["role"] for check in report.checks}
        if observed and len(observed) < len(ROLES):
            report.exit_code = max(report.exit_code, 3)
        for role in ROLES:
            if role not in observed:
                report.checks.append(
                    {
                        "role": role,
                        "status": "not_run",
                        "exit_code": None,
                        "reason_codes": ["required_not_run"],
                    }
                )
        report.checks.sort(key=lambda check: ROLES.index(check["role"]))
    return report.emit(json_mode)
