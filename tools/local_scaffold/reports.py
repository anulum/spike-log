# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Closed, deterministic diagnostics for the local infrastructure CLI."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal, TextIO, TypedDict, cast

from .policy import DETAILS, MAX_REPORT, ROLES

type Exit = Literal[0, 2, 3, 4]
type Status = Literal["passed", "refused", "unavailable", "invalid", "not_run"]
type Scope = Literal[
    "local_scaffold",
    "inventory_generate",
    "audit_produce",
    "provenance_inputs",
    "provenance_candidate",
    "provenance_comparison",
]


class Reason(TypedDict):
    """An authored condition and an optional safe lexical input location.

    Attributes
    ----------
    code : str
        Fixed authored refusal/unavailability/configuration identity.
    location : str | None
        Safe relative lexical location, or None when absent/unsafe.
    detail : str
        Fixed authored explanation from DETAILS, never received input text.
    """

    code: str
    location: str | None
    detail: str


class Check(TypedDict):
    """The observed result of exactly one required preflight role.

    Attributes
    ----------
    role : str
        Required preflight role identity.
    status : Status
        Observed native outcome, including not_run when no execution occurred.
    exit_code : Exit | None
        Native admitted exit, or None for not_run.
    reason_codes : list[str]
        Complete fixed reasons associated with this role outcome.
    """

    role: str
    status: Status
    exit_code: Exit | None
    reason_codes: list[str]


class Wire(TypedDict):
    """The exact typed transport record admitted by the semantic boundary.

    Attributes
    ----------
    report_schema : str
        Exact local-scaffold guard report schema identifier.
    gate : str
        Implemented producer identity; not an evidence or scientific authority.
    scope : str
        Declared local operation scope.
    status : Status
        Status corresponding to native exit precedence.
    exit_code : Exit
        Admitted native exit0/2/3/4.
    reasons : list[Reason]
        Ordered bounded fixed reasons with sanitised lexical locations.
    checks : list[Check]
        Complete observed role outcomes when required by the preflight operation.
    """

    report_schema: str
    gate: str
    scope: str
    status: Status
    exit_code: Exit
    reasons: list[Reason]
    checks: list[Check]


class Fault(Exception):
    """Carry only authored diagnostic identity across an input boundary.

    Attributes
    ----------
    code : str
        Fixed authored condition carried across an input/tool boundary.
    location : str | None
        Lexical input location, sanitised before Report emission.
    exit_code : Exit
        Authored native precedence contribution.
    """

    def __init__(self, code: str, location: str | None = None, exit_code: Exit = 2) -> None:
        """Record authored diagnostic fields for later safe report emission.

        Parameters
        ----------
        code : str
            Caller-authored fixed diagnostic identity; no received secret/data payload is retained.
        location : str | None
            Optional lexical input location; Report.add sanitises it before public emission.
        exit_code : Exit
            Authored native outcome in the admitted 0,2,3,4 exit set, default refusal2.
        """
        super().__init__(code)
        self.code = code
        self.location = location
        self.exit_code = exit_code


class DiagnosticLimit(Exception):
    """Stop scanning immediately after the fixed final diagnostic is recorded."""


def safe_location(value: str | None) -> str | None:
    """Return a relative scalar-Unicode location, or discard unsafe locations.

    Parameters
    ----------
    value : str | None
        Optional received lexical location evaluated for relative path, scalar Unicode and 1024-byte safety.

    Returns
    -------
    str | None
        Original admitted relative location, or None for any unsafe/absent location.
    """
    if value is None:
        return None
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        return None
    if any(ord(c) < 32 or 127 <= ord(c) < 160 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        return None
    if len(value.encode("utf-8")) > 1024:
        return None
    return value


def status_for(code: int) -> Status:
    """Map the four public native exits to their exact scoped statuses.

    Parameters
    ----------
    code : int
        Native exit in the admitted set 0, 2, 3, 4.

    Returns
    -------
    Status
        Exactly passed/refused/unavailable/invalid for the corresponding native exit.

    Raises
    ------
    KeyError
        Raised for an exit outside the fixed admitted mapping.
    """
    statuses: dict[int, Status] = {0: "passed", 2: "refused", 3: "unavailable", 4: "invalid"}
    return statuses[code]


@dataclass(slots=True)
class Report:
    """Accumulate bounded observations without dropping earlier failures.

    Attributes
    ----------
    gate : str
        Fixed implemented guard producer.
    scope : str
        Declared local operation, default local_scaffold.
    exit_code : Exit
        Maximum admitted exit precedence observed so far.
    reasons : list[Reason]
        Ordered finite safe reasons; exhaustion is an explicit DiagnosticLimit.
    checks : list[Check]
        Actual required-role observations, preserving failures and not_run.
    """

    gate: str
    scope: str = "local_scaffold"
    exit_code: Exit = 0
    reasons: list[Reason] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)

    def add(self, code: str, location: str | None = None, exit_code: Exit = 2) -> None:
        """Append a fixed reason, refusing further discovery at the reason limit.

        Parameters
        ----------
        code : str
            Fixed authored condition present in DETAILS; received diagnostic text is not accepted.
        location : str | None
            Optional lexical input location used for a safe diagnostic; received values are never echoed.
        exit_code : Exit
            Outcome precedence contribution from the admitted 0/2/3/4 exit set.

        Raises
        ------
        DiagnosticLimit
            Raised at the fixed final reason budget after recording diagnostic_budget_exceeded.
        """
        self.exit_code = max(self.exit_code, exit_code)
        if len(self.reasons) >= 256:
            raise DiagnosticLimit
        if len(self.reasons) == 255:
            code, location, exit_code = "diagnostic_budget_exceeded", None, 2
        self.reasons.append(
            {"code": code, "location": safe_location(location), "detail": DETAILS[code]}
        )
        if len(self.reasons) == 256:
            raise DiagnosticLimit

    def observe(self, fault: Fault) -> None:
        """Retain an input fault under the same precedence as tool outcomes.

        Parameters
        ----------
        fault : Fault
            Authored Fault whose code/location/exit are added under the same reason budget.

        Raises
        ------
        DiagnosticLimit
            Raised when adding this observation exhausts the finite reason budget.
        """
        self.add(fault.code, fault.location, fault.exit_code)

    def payload(self) -> Wire:
        """Produce precisely the closed seven-field report wire object.

        Returns
        -------
        Wire
            Exact seven-field local-scaffold diagnostic object referencing this report's accumulated reasons/checks.
        """
        return {
            "report_schema": "spike_log.local-scaffold-guard-report.v1",
            "gate": self.gate,
            "scope": self.scope,
            "status": status_for(self.exit_code),
            "exit_code": self.exit_code,
            "reasons": self.reasons,
            "checks": self.checks,
        }

    def emit(self, json_mode: bool) -> Exit:
        """Write a finite report; a closed consumer can never receive exit zero.

        Parameters
        ----------
        json_mode : bool
            Emit deterministic seven-field JSON when true, otherwise readable fixed-code text.

        Returns
        -------
        Exit
            Report exit after successful bounded flush, or 2 when the consumer/output fails; a broken pipe cannot pass.
        """
        try:
            if json_mode:
                output = (
                    json.dumps(self.payload(), sort_keys=True, ensure_ascii=True, allow_nan=False)
                    + "\n"
                )
            else:
                output = f"{self.gate}: {status_for(self.exit_code)} ({self.scope})\n"
                output += "".join(f"{r['code']}: {r['detail']}\n" for r in self.reasons)
            if len(output.encode("utf-8")) > MAX_REPORT:
                raise OSError
            sys.stdout.write(output)
            sys.stdout.flush()
        except (OSError, ValueError):
            try:
                descriptor = os.open(os.devnull, os.O_WRONLY)
                try:
                    os.dup2(descriptor, cast(TextIO, sys.stdout).fileno())
                finally:
                    os.close(descriptor)
            except (OSError, ValueError):
                pass
            try:
                sys.stderr.write("output_failure: report emission failed.\n")
                sys.stderr.flush()
            except (OSError, ValueError):
                return 2
            return 2
        return self.exit_code


def validate_child(
    value: object,
    gate: str,
    native_exit: int,
    *,
    expected_scope: Scope = "local_scaffold",
) -> Wire:
    """Reject schema-valid but semantically incomplete or contradictory reports.

    Parameters
    ----------
    value : object
        Decoded child candidate requiring the exact seven-field schema and semantic invariants.
    gate : str
        Expected child guard identity; input cannot rename its producer.
    native_exit : int
        Actual child process exit that must agree with the received report.
    expected_scope : Scope
        Trusted expected operation, never inferred from the received report. Inventory generation
        belongs to repository_inventory, audit production to dependency_alignment, and all three
        provenance operation scopes to provenance_reproduction. The default remains local_scaffold.

    Returns
    -------
    Wire
        Admitted semantically complete child report, without coercing contradiction or missing required outcomes.

    Raises
    ------
    Fault
        Raised as child_report_invalid for malformed records or child_status_mismatch
        for contradictory status, native exit, reasons or role outcomes.
    """
    scope_owners = {
        "inventory_generate": "repository_inventory",
        "audit_produce": "dependency_alignment",
        "provenance_inputs": "provenance_reproduction",
        "provenance_candidate": "provenance_reproduction",
        "provenance_comparison": "provenance_reproduction",
    }
    if expected_scope != "local_scaffold" and scope_owners.get(expected_scope) != gate:
        raise Fault("child_report_invalid")
    if not isinstance(value, dict) or set(value) != {
        "report_schema",
        "gate",
        "scope",
        "status",
        "exit_code",
        "reasons",
        "checks",
    }:
        raise Fault("child_report_invalid")
    if (
        value["report_schema"] != "spike_log.local-scaffold-guard-report.v1"
        or value["gate"] != gate
    ):
        raise Fault("child_report_invalid")
    if value["scope"] != expected_scope or type(value["exit_code"]) is not int:
        raise Fault("child_report_invalid")
    code = value["exit_code"]
    if code not in (0, 2, 3, 4) or value["status"] != status_for(code):
        raise Fault("child_status_mismatch")
    if code != native_exit:
        raise Fault("child_status_mismatch")
    reasons, checks = value["reasons"], value["checks"]
    if not isinstance(reasons, list) or len(reasons) > 256 or not isinstance(checks, list):
        raise Fault("child_report_invalid")
    for reason in reasons:
        if not isinstance(reason, dict) or set(reason) != {"code", "location", "detail"}:
            raise Fault("child_report_invalid")
        reason_code, location = reason["code"], reason["location"]
        if not isinstance(reason_code, str) or reason_code not in DETAILS:
            raise Fault("child_report_invalid")
        if reason["detail"] != DETAILS[reason_code]:
            raise Fault("child_report_invalid")
        if location is not None and (
            not isinstance(location, str) or safe_location(location) != location
        ):
            raise Fault("child_report_invalid")
    if (code == 0) != (not reasons):
        raise Fault("child_status_mismatch")
    if gate != "preflight":
        if checks:
            raise Fault("child_report_invalid")
    else:
        if len(checks) != len(ROLES):
            raise Fault("child_report_invalid")
        exits: list[int] = []
        for role, check in zip(ROLES, checks, strict=True):
            if not isinstance(check, dict) or set(check) != {
                "role",
                "status",
                "exit_code",
                "reason_codes",
            }:
                raise Fault("child_report_invalid")
            if check["role"] != role:
                raise Fault("child_report_invalid")
            codes = check["reason_codes"]
            if (
                not isinstance(codes, list)
                or len(codes) > 256
                or any(not isinstance(c, str) or c not in DETAILS for c in codes)
            ):
                raise Fault("child_report_invalid")
            child_exit = check["exit_code"]
            if check["status"] == "not_run":
                if child_exit is not None or codes != ["required_not_run"]:
                    raise Fault("child_status_mismatch")
                exits.append(3)
            elif type(child_exit) is not int or child_exit not in (0, 2, 3, 4):
                raise Fault("child_status_mismatch")
            else:
                if check["status"] != status_for(child_exit) or (child_exit == 0) != (not codes):
                    raise Fault("child_status_mismatch")
                exits.append(child_exit)
        if max(exits) != code:
            prerequisite_exits = {
                "invocation_invalid": 4,
                "configuration_invalid": 4,
                "root_symlink": 2,
                "root_unavailable": 3,
                "source_identity_mismatch": 2,
                "policy_refusal": 2,
                "tool_unavailable": 3,
                "input_unavailable": 3,
                "unexpected_fault": 2,
            }
            if not (
                all(check["status"] == "not_run" for check in checks)
                and code != 0
                and all(reason["code"] in prerequisite_exits for reason in reasons)
                and max(prerequisite_exits[reason["code"]] for reason in reasons) == code
            ):
                raise Fault("child_status_mismatch")
    return cast(Wire, value)
