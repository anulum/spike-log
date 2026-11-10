# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check shared native exits and untrusted input boundaries on six public guards."""

import subprocess
from pathlib import Path

import pytest

from tests.conftest import SOURCE, closed_stdout, payload, run_guard, snapshots, source_python

INPUTS = {
    "repository_metadata": "repository-domain.json",
    "source_provenance": "dependency-provenance.json",
    "workflow_policy": "workflow-policy.json",
    "dependency_alignment": "dependency-provenance.json",
    "documentation": ".github/FUNDING.yml",
    "repository_inventory": "repository-domain.json",
}


@pytest.mark.parametrize("gate", list(INPUTS))
@pytest.mark.parametrize(
    "case",
    [
        "root-absent",
        "root-link",
        "unknown-option",
        "utf8",
        "controls",
        "oversize",
        "missing",
        "duplicate",
        "broken-stdout",
    ],
)
def test_common_closed_boundaries(root: Path, tmp_path: Path, gate: str, case: str) -> None:
    """Use real filesystem, raw input and pipe changes at each applicable surface."""
    if case == "broken-stdout":
        assert closed_stdout(gate, root) == 2
        return
    expected = 2
    arguments: tuple[str, ...] = ()
    selected = root
    if case == "root-absent":
        selected = tmp_path / "absent"
        expected = 3
    elif case == "root-link":
        selected = tmp_path / "link"
        selected.symlink_to(root, target_is_directory=True)
    elif case == "unknown-option":
        arguments = ("--private-sentinel",)
        expected = 4
    else:
        path = root / INPUTS[gate]
        if case == "missing":
            path.unlink()
            expected = 3
        elif case == "utf8":
            path.write_bytes(b"\xff")
        elif case == "controls":
            path.write_bytes(b"\x1bprivate-sentinel")
        elif case == "oversize":
            path.write_bytes(b" " * 1048577)
        else:
            path.write_text(
                "same: 1\nsame: 2\n" if gate == "documentation" else '{"same":1,"same":2}\n'
            )
    result = run_guard(gate, selected, *arguments)
    payload(result, expected)
    assert b"private-sentinel" not in result.stdout
    assert str(root).encode() not in result.stdout


def test_importing_public_entrypoints_is_inert(root: Path) -> None:
    """Loading every real public script as a module emits nothing and changes no input."""
    before = snapshots(root)
    program = """import pathlib,runpy,sys
sys.path.insert(0,sys.argv[1])
directory=pathlib.Path(sys.argv[1])
sys.argv=['module-import','--unknown-option','--root',sys.argv[2]]
for name in ('repository_metadata','source_provenance','workflow_policy','dependency_alignment','documentation','repository_inventory'):
    namespace=runpy.run_path(directory/('check_'+name+'.py'),run_name='imported_public_guard')
    assert callable(namespace['main'])
namespace=runpy.run_path(directory/'preflight.py',run_name='imported_public_preflight')
assert callable(namespace['main'])
"""
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools"), str(root)),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0 and result.stdout == result.stderr == b""
    assert snapshots(root) == before


@pytest.mark.parametrize("gate", [*INPUTS, "preflight"])
def test_imported_public_entrypoint_has_fixed_operation(root: Path, gate: str) -> None:
    """Imported commands refuse invalid options under their own public identity."""
    before = snapshots(root)
    filename = "preflight.py" if gate == "preflight" else "check_" + gate + ".py"
    program = """import pathlib,runpy,sys
sys.path.insert(0,sys.argv[1])
namespace=runpy.run_path(pathlib.Path(sys.argv[1])/sys.argv[2],run_name='imported_public_guard')
sys.exit(namespace['main'](arguments=['--root',sys.argv[3],'--json','--private-sentinel']))
"""
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools"), filename, str(root)),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    report = payload(result, 4)
    assert report["gate"] == gate
    assert b"private-sentinel" not in result.stdout
    assert snapshots(root) == before


def test_public_dispatch_refuses_unsupported_operation(root: Path) -> None:
    """An unsupported trusted operation returns invalid configuration before input use."""
    before = snapshots(root)
    program = """import sys
sys.path.insert(0,sys.argv[1])
from local_scaffold.cli import main
sys.exit(main('unsupported_guard',['--root',sys.argv[2],'--json']))
"""
    result = subprocess.run(
        source_python("-c", program, str(SOURCE / "tools"), str(root)),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    report = payload(result, 4)
    assert report["gate"] == "unsupported_guard"
    assert report["reasons"] == [
        {
            "code": "configuration_invalid",
            "detail": "Required local infrastructure condition failed: configuration_invalid.",
            "location": None,
        }
    ]
    assert snapshots(root) == before
