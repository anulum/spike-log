# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual installation and source-context binding through the public consumer."""

import hashlib
import json
import subprocess
from pathlib import Path
from time import monotonic, sleep

import pytest

from local_scaffold.audit_context import policy_digest
from local_scaffold.inputs import Json
from local_scaffold.reports import Fault
from tests.conftest import (
    SOURCE,
    adverse_audit_receipt,
    clone_dependency,
    payload,
    run_guard,
    snapshots,
    source_python,
)
from tests.test_environment_failures import actual_unsupported_python as actual_unsupported_python
from tests.test_environment_failures import genuine_graph_lock, qualify_complete_graph
from tests.test_environment_failures import genuine_graph_python as genuine_graph_python


def test_foreign_genuine_admission_is_not_local_trust(audited_clone: Path) -> None:
    """Unmodified genuine foreign objects refuse in a distinct actual installation."""
    result = payload(clone_dependency(audited_clone), 2)
    assert result["reasons"]


@pytest.mark.parametrize(
    "field",
    [
        "registry_graph_sha256",
        "trusted_policy_sha256",
        "installed_metadata_sha256",
        "python_executable_sha256",
    ],
)
def test_changed_context_refuses_adverse_owned_receipt(audited_clone: Path, field: str) -> None:
    """Each independently changed valid digest refuses before receipt freshness can pass."""
    adverse_audit_receipt(audited_clone, {field: "0" * 64})
    payload(clone_dependency(audited_clone), 2)


@pytest.mark.parametrize("field", ["producer", "producer_version", "python_version"])
def test_changed_producer_or_runtime_identity_refuses(audited_clone: Path, field: str) -> None:
    """A version string or producer name cannot substitute for current measured identity."""
    changes: dict[str, Json] = {field: "unadmitted"}
    adverse_audit_receipt(audited_clone, changes)
    payload(clone_dependency(audited_clone), 2)


def test_inspected_store_cannot_select_consumer_trust(audited_clone: Path) -> None:
    """The canonical consumer ignores a received store even when its HEAD is damaged."""
    (audited_clone / ".tool-cache/security-admissions/HEAD.json").write_bytes(b"not JSON")
    payload(run_guard("dependency_alignment", audited_clone), 0)


def test_actual_changed_tool_source_invalidates_admission(audited_clone: Path) -> None:
    """A real trusted-tool source change refuses before an adverse terminal outcome is read."""
    adverse_audit_receipt(audited_clone, {"outcome": "unavailable"})
    with (audited_clone / "tools/check_repository_metadata.py").open("ab") as stream:
        stream.write(b"\n# Changed owned negative source fixture.\n")
    payload(clone_dependency(audited_clone), 2)


@pytest.mark.parametrize("source_count", [512, 513])
def test_complete_trusted_tool_source_budget(audited_clone: Path, source_count: int) -> None:
    """Read all allowed source bodies and refuse the first source beyond the fixed limit."""
    tools = audited_clone / "tools"
    existing = len(list(tools.rglob("*.py")))
    assert existing < 512
    for index in range(source_count - existing):
        (tools / f"owned_source_{index}.py").write_bytes(b"\n")
    result = payload(clone_dependency(audited_clone), 2)
    reasons = str(result["reasons"])
    expected = "resource_limit" if source_count == 513 else "source_identity_mismatch"
    assert expected in reasons
    assert ("resource_limit" in reasons) == (source_count == 513)
    assert "unexpected_fault" not in reasons


def test_changed_original_provenance_bytes_refuse_context(audited_clone: Path) -> None:
    """Equivalent JSON cannot replace the original producer metadata bytes in admission."""
    provenance = audited_clone / "dependency-provenance.json"
    with provenance.open("ab") as stream:
        stream.write(b"\n")
    result = payload(clone_dependency(audited_clone), 2)
    assert "source_identity_mismatch" in str(result["reasons"])
    assert "unexpected_fault" not in str(result["reasons"])


@pytest.mark.parametrize(
    "transition",
    [
        "unchanged",
        "missing-metadata",
        "invalid-name",
        "invalid-version",
        "duplicate-name",
        "changed-metadata",
        "empty-tools",
    ],
)
def test_public_context_reads_actual_source_and_producer_transitions(
    audited_clone: Path,
    genuine_graph_python: Path,
    tmp_path: Path,
    transition: str,
) -> None:
    """Invoke the complete context API after independently changing actual owned inputs."""
    prefix = genuine_graph_python.parents[1]
    with genuine_graph_lock(prefix.parent):
        qualify_complete_graph(genuine_graph_python)
        metadata = prefix / "lib/python3.13/site-packages/zizmor-1.30.1.dist-info/METADATA"
        original = metadata.read_bytes()
        held = metadata.with_name("METADATA.context-original")
        assert not held.exists()
        tools = audited_clone / "tools"
        held_tools = audited_clone / "actual-context-tools-retained"
        assert not held_tools.exists()
        source_before = snapshots(audited_clone)
        ready, resume, output = (
            tmp_path / "context-imported",
            tmp_path / "context-invoke",
            tmp_path / "actual-context.json",
        )
        program = """import json,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from local_scaffold.audit_context import context
from local_scaffold.reports import Fault,Report
ready,resume,output=map(Path,sys.argv[2:])
ready.write_bytes(b'actual-context-api-imported\\n')
deadline=time.monotonic()+10
while not resume.exists():
    assert time.monotonic()<deadline
    time.sleep(0.001)
report=Report('dependency_alignment',scope='audit_context_api')
try:
    material=context()
    output.write_text(json.dumps(material,sort_keys=True)+'\\n')
except Fault as fault:
    report.observe(fault)
sys.exit(report.emit(True))
"""
        command = source_python(
            "-I",
            "-c",
            program,
            str(tools),
            str(ready),
            str(resume),
            str(output),
            executable=str(genuine_graph_python),
        )
        with subprocess.Popen(
            command, cwd=audited_clone, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            try:
                deadline = monotonic() + 10
                while not ready.exists():
                    assert process.poll() is None
                    assert monotonic() < deadline
                    sleep(0.001)
                if transition == "empty-tools":
                    tools.rename(held_tools)
                    tools.mkdir()
                elif transition != "unchanged":
                    metadata.rename(held)
                    if transition != "missing-metadata":
                        changes = {
                            "invalid-name": (b"Name: zizmor\n", b"Name:\n"),
                            "invalid-version": (b"Version: 1.30.1\n", b"Version:\n"),
                            "duplicate-name": (b"Name: zizmor\n", b"Name: packaging\n"),
                            "changed-metadata": (
                                b"Name: zizmor\n",
                                b"Name: zizmor\nX-Owned-Negative: changed\n",
                            ),
                        }
                        old, new = changes[transition]
                        changed = original.replace(old, new, 1)
                        assert changed != original
                        metadata.write_bytes(changed)
                resume.write_bytes(b"invoke-actual-context\n")
                stdout, stderr = process.communicate(timeout=30)
                record = payload(
                    subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr),
                    0 if transition == "unchanged" else 2,
                )
                assert record["scope"] == "audit_context_api"
                if transition == "unchanged":
                    current = json.loads(output.read_bytes())
                    fields = {
                        "registry_graph_sha256",
                        "trusted_policy_sha256",
                        "installed_metadata_sha256",
                        "python_version",
                        "python_executable_sha256",
                        "installation_sha256",
                    }
                    assert set(current) == fields
                    store = SOURCE / ".tool-cache/security-admissions"
                    head = json.loads((store / "HEAD.json").read_bytes())
                    receipt = json.loads(
                        (store / "objects" / (head["receipt_sha256"] + ".json")).read_bytes()
                    )
                    for name in fields - {"installation_sha256"}:
                        assert current[name] == receipt[name]
                    assert (
                        current["installation_sha256"]
                        == hashlib.sha256(
                            b"spike_log.trusted-installation.v1\0" + str(audited_clone).encode()
                        ).hexdigest()
                    )
                else:
                    expected = (
                        "resource_limit"
                        if transition == "empty-tools"
                        else "dependency_alignment.wrong-producer"
                    )
                    assert record["reasons"] == [
                        {
                            "code": expected,
                            "location": None
                            if transition == "empty-tools"
                            else "dependency-provenance.json",
                            "detail": "Required local infrastructure condition failed: "
                            + expected
                            + ".",
                        }
                    ]
                    assert not output.exists()
            finally:
                process.terminate()
                process.wait(timeout=5)
                if held.exists():
                    if metadata.exists():
                        metadata.rename(tmp_path / "actual-adverse-METADATA.preserved")
                    held.rename(metadata)
                if held_tools.exists():
                    tools.rmdir()
                    held_tools.rename(tools)
        assert metadata.read_bytes() == original
        assert snapshots(audited_clone) == source_before
        qualify_complete_graph(genuine_graph_python)


def test_public_context_rejects_genuine_unsupported_runtime(
    actual_unsupported_python: Path,
) -> None:
    """Exercise the public complete context API under each genuine unsupported CPython."""
    program = """import sys
sys.path.insert(0,sys.argv[1])
from local_scaffold.audit_context import context
from local_scaffold.reports import Fault,Report
report=Report('dependency_alignment')
try:
    context()
except Fault as fault:
    report.observe(fault)
sys.exit(report.emit(True))
"""
    result = subprocess.run(
        source_python(
            "-I", "-c", program, str(SOURCE / "tools"), executable=str(actual_unsupported_python)
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    record = payload(result, 2)
    assert record["reasons"] == [
        {
            "code": "dependency_alignment.incompatible-patch",
            "location": "dependency-provenance.json",
            "detail": "Required local infrastructure condition failed: "
            "dependency_alignment.incompatible-patch.",
        }
    ]


def test_policy_digest_refuses_a_tooling_tree_without_python_sources(tmp_path: Path) -> None:
    """A trusted installation whose tools tree holds no Python source has nothing to bind."""
    (tmp_path / "tools/local_scaffold").mkdir(parents=True)
    (tmp_path / "tools/README.txt").write_text("No Python source.\n")
    with pytest.raises(Fault) as raised:
        policy_digest(tmp_path)
    assert raised.value.code == "resource_limit"
