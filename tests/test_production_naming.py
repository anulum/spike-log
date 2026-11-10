# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise naming refusals through complete real public guard inputs."""

import json
from pathlib import Path

import pytest

from local_scaffold.inputs import Json
from tests.conftest import SOURCE, change, payload, run_guard, snapshots


def rejected_identifier(separator: str = "_") -> str:
    """Construct received negative input without declaring a production alias."""
    return separator.join(("BL", "19"))


def maintained_python(root: Path, name: str, body: str) -> None:
    """Write an actual fixture with the owning source notice and module docstring."""
    header = "\n".join(
        (SOURCE / "tools/check_repository_inventory.py").read_text().splitlines()[:7]
    )
    (root / name).write_text(header + '\n\n"""Received module under inspection."""\n' + body)


def reason_codes(value: dict[str, Json]) -> set[str]:
    """Read actual report codes while asserting their native decoded types."""
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    codes: set[str] = set()
    for reason in reasons:
        assert isinstance(reason, dict)
        code = reason["code"]
        assert isinstance(code, str)
        codes.add(code)
    return codes


@pytest.mark.parametrize(
    "body",
    [
        "class {token}:\n    pass\n",
        "def {token}():\n    return 0\n",
        "async def {token}():\n    return 0\n",
        "{token} = 0\n",
        "value = received.{token}\n",
        "def inspect({token}):\n    return 0\n",
        "import os as {token}\n",
        "from received import {token}\n",
        "value = dict({token}=0)\n",
        "def inspect():\n    global {token}\n    return 0\n",
        "def outer():\n    {token}=0\n    def inner():\n        nonlocal {token}\n        return 0\n",
        "value = '{token}'\n",
        "value = 'BL\\u002d19'\n",
    ],
    ids=[
        "class",
        "function",
        "async-function",
        "variable",
        "attribute",
        "parameter",
        "import-alias",
        "incoming-consumer",
        "keyword",
        "global",
        "nonlocal",
        "runtime-message",
        "escaped-runtime-message",
    ],
)
def test_python_declarations_and_consumers_are_refused(root: Path, body: str) -> None:
    """Refuse actual decoded declarations and strings without executing the input."""
    maintained_python(root, "tools/received_surface.py", body.format(token=rejected_identifier()))
    before = snapshots(root)
    value = payload(run_guard("repository_inventory", root), 2)
    assert "policy_refusal" in reason_codes(value)
    assert snapshots(root) == before


@pytest.mark.parametrize("surface", ["module", "directory", "catalogue", "schema", "toml", "yaml"])
def test_complete_owned_population_is_inspected(root: Path, surface: str) -> None:
    """Include unlisted incoming files and decoded configuration/evidence values."""
    token = rejected_identifier("-")
    if surface == "module":
        maintained_python(root, "tools/" + token + ".py", "value=0\n")
    elif surface == "directory":
        directory = root / token
        directory.mkdir()
        maintained_python(root, token + "/received.py", "value=0\n")
    elif surface == "catalogue":
        path = root / "received-catalogue.json"
        path.write_text(json.dumps({"records": [{"command": token}]}) + "\n")
        path.with_name(path.name + ".license").write_bytes(
            (SOURCE / "repository-domain.json.license").read_bytes()
        )
    elif surface == "schema":
        change(root, "schemas/repository-domain.schema.json", ("$id",), token)
    elif surface == "toml":
        path = root / "gitleaks.toml"
        path.write_text(path.read_text() + '\nreceived = "BL\\u002d19"\n')
    else:
        path = root / ".github/ISSUE_TEMPLATE/config.yml"
        path.write_text(path.read_text() + '\nreceived: "BL\\u002d19"\n')
    value = payload(run_guard("repository_inventory", root), 2)
    assert "policy_refusal" in reason_codes(value)


def test_coded_metadata_and_workflow_values_are_refused(root: Path) -> None:
    """Observe naming conditions from the owning metadata and workflow guards."""
    change(root, "repository-domain.json", ("claims",), [rejected_identifier("-")])
    metadata = payload(run_guard("repository_metadata", root), 2)
    assert "policy_refusal" in reason_codes(metadata)
    path = root / ".github/workflows/ci.yml"
    path.write_text(path.read_text().replace("name: CI", "name: " + rejected_identifier("-")))
    workflow = payload(run_guard("workflow_policy", root), 2)
    assert "policy_refusal" in reason_codes(workflow)


def test_rendered_documentation_refuses_escaped_private_names(root: Path) -> None:
    """Decoded HTML text cannot conceal the same rejected public vocabulary."""
    path = root / "README.md"
    path.write_text(path.read_text() + "\n" + "BL&#45;19" + "\n")
    value = payload(run_guard("documentation", root), 2)
    assert "policy_refusal" in reason_codes(value)


@pytest.mark.parametrize(
    "body",
    [
        "{{ 'BL\\u002d19' }}",
        "<span>BL&#45;19</span>",
        "{{ received_identifier }}",
        "{{ ['BL\\u002d19', 19, true] }}",
    ],
)
def test_native_templates_refuse_decoded_private_names(root: Path, body: str) -> None:
    """Native Jinja fields and decoded HTML entities cannot conceal queue names."""
    (root / "received.html").write_text(body.replace("received_identifier", rejected_identifier()))
    before = snapshots(root)
    value = payload(run_guard("repository_inventory", root), 2)
    assert "policy_refusal" in reason_codes(value)
    assert snapshots(root) == before


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("{% unfinished %}", "scan_incomplete"),
        ("{{ " + "[" * 80 + "0" + "]" * 80 + " }}", "resource_limit"),
        ("{{ " + "[" * 1000 + "0" + "]" * 1000 + " }}", "resource_limit"),
        ("{{ [" + ",".join("0" for _ in range(100001)) + "] }}", "resource_limit"),
    ],
    ids=["syntax", "native-node-depth", "native-parser-recursion", "native-node-population"],
)
def test_native_template_inspection_preserves_failures(
    root: Path, body: str, expected: str
) -> None:
    """Malformed or unbounded native template consumers remain refused without rendering."""
    (root / "received.html").write_text(body)
    value = payload(run_guard("repository_inventory", root), 2)
    assert expected in reason_codes(value)


@pytest.mark.parametrize(
    "kind", ["python", "toml", "language", "unexamined-data", "depth", "values"]
)
def test_unexamined_or_unbounded_inputs_cannot_pass(root: Path, kind: str) -> None:
    """Retain native inspection and resource failures for the actual whole tree."""
    expected = "scan_incomplete"
    if kind == "python":
        maintained_python(root, "tools/received_surface.py", "def unfinished(\n")
    elif kind == "language":
        (root / "received_consumer.rs").write_text("pub fn received() {}\n")
    elif kind == "unexamined-data":
        (root / "received-catalogue.xml").write_text('<record name="BL&#45;19"/>\n')
    else:
        path = root / "gitleaks.toml"
        if kind == "toml":
            addition = "\n[unfinished\n"
        elif kind == "depth":
            addition = "\n[" + ".".join("scope" for _ in range(66)) + "]\nvalue=0\n"
            expected = "resource_limit"
        else:
            addition = "\nreceived=[" + ",".join("0" for _ in range(100001)) + "]\n"
            expected = "resource_limit"
        path.write_text(path.read_text() + addition)
    value = payload(run_guard("repository_inventory", root), 2)
    assert expected in reason_codes(value)


@pytest.mark.parametrize(
    ("prefix", "number"),
    [("WS", "1"), ("QWC", "12"), ("CO1_WEB", "008"), ("ARCH_Q", "06"), ("INFRA_SCHEMA", "4")],
)
def test_private_workstream_families_are_refused(root: Path, prefix: str, number: str) -> None:
    """Refuse concrete private workstream names in an actual generated catalogue."""
    path = root / "received-catalogue.json"
    path.write_text(json.dumps({"records": [{"name": prefix + "_" + number}]}) + "\n")
    path.with_name(path.name + ".license").write_bytes(
        (SOURCE / "repository-domain.json.license").read_bytes()
    )
    value = payload(run_guard("repository_inventory", root), 2)
    assert "policy_refusal" in reason_codes(value)


def test_scientific_standards_and_descriptive_names_remain_valid(root: Path) -> None:
    """Accept genuine standard/part vocabulary, typed declarations and consumers."""
    maintained_python(
        root,
        "tools/scientific_identifiers.py",
        "from hashlib import sha256 as digest\n"
        'protocol="SHA-256; ML-DSA-65; TLS 1.3; WS2812"\n'
        "def outer():\n"
        "    observed=0\n"
        "    def inner():\n"
        "        nonlocal observed\n"
        "        global protocol\n"
        '        return dict(**{"digest": digest(protocol.encode()).hexdigest()})\n',
    )
    before = snapshots(root)
    payload(run_guard("repository_inventory", root), 0)
    assert snapshots(root) == before


@pytest.mark.parametrize("private", [False, True], ids=["maintained-fragment", "private-name"])
def test_make_fragments_use_public_owned_naming_boundary(root: Path, private: bool) -> None:
    """Inspect real included Make source without executing a received expression."""
    path = root / ".make/quality.mk"
    addition = rejected_identifier() if private else "ordinary_scaffold_quality"
    path.write_text(path.read_text() + "\n" + addition + ":\n\t@true\n")
    before = snapshots(root)
    value = payload(run_guard("repository_inventory", root), 2 if private else 0)
    assert ("policy_refusal" in reason_codes(value)) is private
    assert "scan_incomplete" not in reason_codes(value)
    assert snapshots(root) == before
