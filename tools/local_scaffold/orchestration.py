# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Preserve every required outcome under one bounded nonrecursive preflight plan."""

from __future__ import annotations

import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .actionlint_view import analyse
from .dependencies import native_tool
from .inputs import parse_json, relative_path, root_directory
from .policy import LEAF_SECONDS, PREFLIGHT_SECONDS, ROLES
from .processes import run_process
from .reports import Check, DiagnosticLimit, Exit, Fault, Report, status_for, validate_child


@dataclass(frozen=True, slots=True)
class Role:
    """A trusted explicit command, its role and its native report contract.

    Attributes
    ----------
    name : str
        Exactly one required authored role identity.
    command : tuple[str, ...]
        Trusted exec-only argument tuple; received files cannot supply a program.
    reported_gate : str | None
        Expected native seven-field guard producer, or None for ordinary native tools.
    working_directory : Path | None
        Trusted child working directory override, or the plan root.
    workflow_root : Path | None
        Original bounded workflow input for the actionlint semantic view only.
    licence_root : Path | None
        Original public byte cohort for the real REUSE view only.
    """

    name: str
    command: tuple[str, ...]
    reported_gate: str | None = None
    working_directory: Path | None = None
    workflow_root: Path | None = None
    licence_root: Path | None = None


def run_plan(
    root: Path, report: Report, roles: tuple[Role, ...], budget: float = PREFLIGHT_SECONDS
) -> None:
    """Run a complete trusted plan and preserve failures, interruption and not_run.

    Repository files never choose commands. A caller-authorised finite plan can
    exercise this orchestration API without claiming those children are genuine
    lint, test or security tools. Native guard reports additionally require exact
    schema, semantic, gate and native-exit agreement before being accepted.
    Each executed role is recorded before its diagnostics are aggregated. A full
    diagnostic budget stops further children while preserving all role outcomes.
    Unexpected native failures are recorded for the current executed role and
    stop later children because their resource cleanup cannot be certified.

    Parameters
    ----------
    root : Path
        Default working directory for the caller-authorised finite role plan.
    report : Report
        Receives every required role outcome and fixed native/report failure reason; not_run is retained.
    roles : tuple[Role, ...]
        Complete ordered tuple matching ROLES, with trusted argv and optional original workflow/licence roots.
    budget : float
        Positive inclusive whole-plan seconds, at most PREFLIGHT_SECONDS; cleanup shares each remaining leaf budget.

    Raises
    ------
    Fault
        Raised for invalid ordering/budget, recursive preflight commands or a special native root assigned to the wrong role.
    """
    if (
        tuple(role.name for role in roles) != tuple(ROLES)
        or isinstance(budget, bool)
        or not math.isfinite(budget)
        or budget <= 0
        or budget > PREFLIGHT_SECONDS
    ):
        raise Fault("configuration_invalid", exit_code=4)
    if (
        any(
            any(Path(argument).name == "preflight.py" for argument in role.command)
            for role in roles
        )
        or any(role.workflow_root is not None and role.name != "actionlint" for role in roles)
        or any(role.licence_root is not None and role.name != "reuse_licence" for role in roles)
    ):
        raise Fault("configuration_invalid", exit_code=4)
    deadline = time.monotonic() + budget
    stopped = False
    for role in roles:
        remaining = deadline - time.monotonic()
        outcome: Check = {
            "role": role.name,
            "status": "not_run",
            "exit_code": None,
            "reason_codes": ["required_not_run"],
        }
        if remaining <= 0 or stopped:
            report.checks.append(outcome)
            try:
                report.add("required_not_run", exit_code=3)
            except DiagnosticLimit:
                stopped = True
            continue
        code: Exit = 0
        codes: list[str] = []
        diagnostics: list[Fault] = []
        try:
            if role.workflow_root is not None:
                result = analyse(role.workflow_root, min(LEAF_SECONDS, remaining))
            elif role.licence_root is not None:
                from .provenance import analyse_reuse

                result = analyse_reuse(role.licence_root, min(LEAF_SECONDS, remaining))
            else:
                result = run_process(
                    list(role.command), role.working_directory or root, min(LEAF_SECONDS, remaining)
                )
            if role.reported_gate is not None:
                child = validate_child(
                    parse_json(result.stdout), role.reported_gate, result.exit_code
                )
                code = child["exit_code"]
                for reason in child["reasons"]:
                    codes.append(reason["code"])
                    diagnostics.append(Fault(reason["code"], reason["location"], code))
            elif result.exit_code != 0:
                code, codes = 2, ["tool_failed"]
                diagnostics.append(Fault("tool_failed"))
        except Fault as fault:
            code, codes = fault.exit_code, [fault.code]
            diagnostics.append(fault)
        except KeyboardInterrupt:
            stopped = True
            code, codes = 3, ["interrupted"]
            diagnostics.append(Fault("interrupted", exit_code=3))
        except Exception:
            stopped = True
            code, codes = 2, ["unexpected_fault"]
            diagnostics.append(Fault("unexpected_fault"))
        outcome = {
            "role": role.name,
            "status": status_for(code),
            "exit_code": code,
            "reason_codes": codes,
        }
        report.checks.append(outcome)
        try:
            for diagnostic in diagnostics:
                report.observe(diagnostic)
        except DiagnosticLimit:
            stopped = True


def configured_roles(root: Path) -> tuple[Role, ...]:
    """Resolve the complete fixed actual tool chain without input-selected programs.

    Secret scanning runs in the received root with relative input paths, so
    an ancestor cache directory cannot hide public files. Its executable and
    configuration still resolve from the trusted source. Received suppression
    files are refused before any child runs, including dangling symbolic links.

    Parameters
    ----------
    root : Path
        Received validated repository whose bounded data is checked; native executables/test imports remain trusted-source owned.

    Returns
    -------
    tuple[Role, ...]
        All fixed required native-role commands, in ROLES order, with original workflow/REUSE roots explicitly bound.

    Raises
    ------
    Fault
        Raised for unsafe root/cache paths or unavailable/changed native-tool producer bytes.
    """
    python = sys.executable
    trusted_source = Path(__file__).resolve().parents[2]
    root = root_directory(str(root))
    if (root / ".gitleaksignore").exists() or (root / ".gitleaksignore").is_symlink():
        raise Fault("policy_refusal", ".gitleaksignore")
    configuration = str(trusted_source / "pyproject.toml")
    # Native plugins, imported test programs and writable tool outputs belong
    # to the trusted implementation. Received repositories supply bounded data.
    for name in (
        ".tool-cache",
        ".tool-cache/mypy",
        ".tool-cache/test-runs",
        ".tool-cache/sbom.json",
    ):
        relative_path(trusted_source, name)
    source_paths = (str(root / "tools"), str(root / "tests"))
    guard_launcher = (
        "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
        "runpy.run_path(sys.argv.pop(1),run_name='__main__')"
    )
    commands: dict[str, tuple[str, ...]] = {}
    for gate in ROLES[:6]:
        commands[gate] = (
            python,
            "-I",
            "-c",
            guard_launcher,
            str(trusted_source / "tools"),
            str(trusted_source / "tools" / ("check_" + gate + ".py")),
            "--root",
            str(root),
            "--json",
        )
    commands.update(
        {
            "python_lint": (
                python,
                "-I",
                "-m",
                "ruff",
                "check",
                "--config",
                configuration,
                "--no-respect-gitignore",
                *source_paths,
            ),
            "python_format": (
                python,
                "-I",
                "-m",
                "ruff",
                "format",
                "--check",
                "--config",
                configuration,
                "--no-respect-gitignore",
                *source_paths,
            ),
            "python_strict_typing": (
                python,
                "-I",
                "-m",
                "mypy",
                "--config-file",
                configuration,
                *source_paths,
            ),
            "python_native_documentation": (
                python,
                "-I",
                "-m",
                "ruff",
                "check",
                "--config",
                configuration,
                "--select",
                "D",
                "--no-respect-gitignore",
                *source_paths,
            ),
            "python_security": (
                python,
                "-I",
                "-m",
                "bandit",
                "--ini",
                "/dev/null",
                "--ignore-nosec",
                "--severity-level",
                "all",
                "--confidence-level",
                "all",
                "-r",
                str(root / "tools"),
                "-f",
                "json",
            ),
            "infrastructure_tests_coverage": (
                python,
                "-I",
                "-m",
                "pytest",
                "-c",
                configuration,
                "--confcutdir",
                str(trusted_source / "tests"),
                "-n",
                "0",
                "--dist=worksteal",
                "--basetemp=.tool-cache/test-runs",
                "--cov=tools",
                "--cov=tests",
                "--cov-branch",
                "--cov-fail-under=100",
                "--cov-report=term-missing",
                str(trusted_source / "tests"),
            ),
            "reuse_licence": (python, "-I", "-m", "reuse", "--root", str(root), "lint", "--json"),
            "secret_scan": (
                str(native_tool("gitleaks")),
                "dir",
                "--redact",
                "--no-banner",
                "--log-level",
                "error",
                "--ignore-gitleaks-allow",
                "--gitleaks-ignore-path",
                "/dev/null",
                "--config",
                str(trusted_source / "gitleaks.toml"),
                ".",
            ),
            "dependency_security": (
                python,
                "-I",
                "-c",
                guard_launcher,
                str(trusted_source / "tools"),
                str(trusted_source / "tools/check_dependency_alignment.py"),
                "--root",
                str(root),
                "--json",
            ),
            "actionlint": (str(native_tool("actionlint")),),
            "workflow_security": (
                str(Path(python).parent / "zizmor"),
                "--no-config",
                "--no-ignores",
                "--strict-collection",
                "--persona",
                "auditor",
                "--offline",
                "--format",
                "json",
                *[str(path) for path in sorted((root / ".github/workflows").glob("*.yml"))],
            ),
            "sbom": (
                python,
                "-I",
                "-m",
                "cyclonedx_py",
                "environment",
                "--output-format",
                "JSON",
                "--output-file",
                ".tool-cache/sbom.json",
                python,
            ),
        }
    )
    return tuple(
        Role(
            name,
            commands[name],
            name if name in ROLES[:6] else None,
            root if name == "secret_scan" else trusted_source,
            root if name == "actionlint" else None,
            root if name == "reuse_licence" else None,
        )
        for name in ROLES
    )


def verify(root: Path, report: Report) -> None:
    """Execute every applicable local role with actual required tooling.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives the complete configured plan outcomes under the original inclusive preflight budget.

    Raises
    ------
    Fault
        Raised if role configuration or trusted producer/root admission fails before execution.
    """
    run_plan(root, report, configured_roles(root))
