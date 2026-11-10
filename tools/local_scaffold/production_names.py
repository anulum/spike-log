# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Inspect maintained names with native parsers and preserve unexamined surfaces."""

from __future__ import annotations

import ast
import re
import tomllib
from html import unescape
from pathlib import Path

from .inputs import parse_json, parse_yaml, read_bytes, read_text
from .limits import MAX_DEPTH, MAX_VALUES
from .reports import Fault, Report

PRIVATE_IDENTIFIER = re.compile(
    r"(?<![a-z0-9])(?:"
    r"(?:bl|ws|qwc|co[0-9]+)[_-](?:[a-z][a-z0-9]*[_-])*[0-9]+[a-z]*"
    r"|(?:arch|infra|host|runtime|rel)[_-](?:[a-z0-9]+[_-])*[a-z]*[0-9]+"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)
INSPECTED_SUFFIXES = {
    "",
    ".py",
    ".pyi",
    ".json",
    ".toml",
    ".yml",
    ".yaml",
    ".cff",
    ".md",
    ".mk",
    ".html",
    ".license",
    ".txt",
    ".in",
}


def check_text(value: str, name: str | None, report: Report) -> None:
    """Refuse known private queue vocabulary without emitting received values.

    This finite recogniser finds private identifiers; absence of a match does
    not attest meaning, provenance or scientific qualification of other names.

    Parameters
    ----------
    value : str
        Received name/text inspected by the finite PRIVATE_IDENTIFIER recogniser.
    name : str | None
        Optional lexical input location used for a safe diagnostic; received values are never echoed.
    report : Report
        Receives policy_refusal without received matched values.
    """
    if PRIVATE_IDENTIFIER.search(value):
        report.add("policy_refusal", name)


def check_values(value: object, name: str, report: Report) -> None:
    """Inspect decoded keys and values with bounded iterative structure traversal.

    Parameters
    ----------
    value : object
        Decoded object whose string keys/values are inspected without execution.
    name : str
        Safe lexical input location for refusal/resource findings.
    report : Report
        Receives private-identifier refusals across the entire bounded decoded structure.

    Raises
    ------
    Fault
        Raised as resource_limit for excessive traversed depth or value population.
    """
    pending = [(value, 0)]
    count = 0
    while pending:
        current, depth = pending.pop()
        count += 1
        if count > MAX_VALUES or depth > MAX_DEPTH:
            raise Fault("resource_limit", name)
        if isinstance(current, str):
            check_text(current, name, report)
        elif isinstance(current, dict):
            for key, child in current.items():
                pending.extend(((key, depth + 1), (child, depth + 1)))
        elif isinstance(current, (list, tuple)):
            pending.extend((child, depth + 1) for child in current)


def python_names(text: str, name: str, report: Report) -> None:
    """Inspect actual Python declarations, consumers and decoded runtime strings.

    Parameters
    ----------
    text : str
        Maintained Python source parsed natively, without importing/executing it.
    name : str
        Lexical source filename used for safe syntax/name findings.
    report : Report
        Receives private identifiers in declarations, imports, consumers and decoded constant strings.

    Raises
    ------
    Fault
        Raised as scan_incomplete when native Python syntax cannot be inspected.
    """
    try:
        module = ast.parse(text, filename=name)
    except (SyntaxError, ValueError) as error:
        raise Fault("scan_incomplete", name) from error
    for node in ast.walk(module):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            check_text(node.name, name, report)
        elif isinstance(node, ast.Name):
            check_text(node.id, name, report)
        elif isinstance(node, ast.Attribute):
            check_text(node.attr, name, report)
        elif isinstance(node, ast.arg):
            check_text(node.arg, name, report)
        elif isinstance(node, ast.alias):
            check_text(node.name, name, report)
            if node.asname is not None:
                check_text(node.asname, name, report)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            check_text(node.arg, name, report)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for identifier in node.names:
                check_text(identifier, name, report)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            check_text(node.value, name, report)


def check_file(root: Path, name: str, report: Report) -> None:
    """Inspect a maintained input; unknown language consumers cannot be admitted.

    Pinned licensed assets and third-party licence text are handled separately
    by provenance. Python and structured configuration use their native parsed
    values as well as raw text, so escaped identifiers remain visible.
    Python outside tools/tests and the enrolled src/spike_log namespace,
    hidden source components and non-lowercase Python extensions remain
    unqualified. Only the exact empty PEP561 marker is a recognized data kind.
    Native MyPy skips site-packages and implementation files shadowed by stubs;
    those source populations also require explicit complete type qualification.
    Makefiles and .mk fragments receive the same finite raw naming inspection;
    this does not evaluate or execute received Make expressions.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    name : str
        Maintained relative filename; unknown suffixes remain unexamined and refused.
    report : Report
        Receives raw/native-decoded private-identifier and unsupported-language findings.

    Raises
    ------
    Fault
        Raised for input failure, invalid native syntax or decoded traversal limits.
    """
    if name == "src/spike_log/py.typed":
        if read_bytes(root, name) != b"":
            report.add("scan_incomplete", name)
        return
    suffix = Path(name).suffix.lower()
    if suffix not in INSPECTED_SUFFIXES:
        report.add("scan_incomplete", name)
        return
    text = read_text(root, name)
    check_text(text, name, report)
    if suffix in {".py", ".pyi"}:
        parts = Path(name).parts
        if (
            (parts[0] not in {"tools", "tests"} and parts[:2] != ("src", "spike_log"))
            or Path(name).suffix != suffix
            or any(part.startswith(".") for part in parts)
            or "site-packages" in parts
            or (suffix == ".py" and (root / name).with_suffix(".pyi").exists(follow_symlinks=False))
        ):
            report.add("scan_incomplete", name)
        python_names(text, name, report)
    elif suffix == ".html":
        template_names(text, name, report)
    elif suffix == ".json":
        check_values(parse_json(read_bytes(root, name), name), name, report)
    elif suffix == ".toml":
        try:
            value = tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise Fault("scan_incomplete", name) from error
        check_values(value, name, report)
    elif suffix in {".yml", ".yaml", ".cff"}:
        check_values(
            parse_yaml(
                read_bytes(root, name), name, workflow=name.startswith(".github/workflows/")
            ),
            name,
            report,
        )


def template_names(text: str, name: str, report: Report) -> None:
    """Inspect native Jinja syntax and decoded HTML without rendering received code.

    Parameters
    ----------
    text : str
        Received Jinja/HTML text inspected by native syntax parsing, never rendering.
    name : str
        Safe lexical template location used for fixed diagnostics.
    report : Report
        Receives private identifiers in native template fields and HTML-decoded strings.

    Raises
    ------
    Fault
        Raised as scan_incomplete for syntax errors or resource_limit for native recursion, depth or population overflow.
    ImportError
        The required native template producer is unavailable; the owning
        public command reports exit 3 without preventing other role outcomes.
    """
    from jinja2 import Environment, TemplateSyntaxError, nodes

    try:
        template = Environment(autoescape=True).parse(text)
    except TemplateSyntaxError as error:
        raise Fault("scan_incomplete", name) from error
    except RecursionError as error:
        raise Fault("resource_limit", name) from error
    pending: list[tuple[object, int]] = [(template, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > MAX_VALUES or depth > MAX_DEPTH:
            raise Fault("resource_limit", name)
        if isinstance(value, str):
            check_text(unescape(value), name, report)
        elif isinstance(value, nodes.Node):
            pending.extend((child, depth + 1) for _, child in value.iter_fields())
        elif isinstance(value, (list, tuple)):
            pending.extend((child, depth + 1) for child in value)
