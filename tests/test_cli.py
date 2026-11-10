# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Exercise actual CLI recovery after producer absence and kernel cleanup denial."""

import json
import re
import subprocess
from pathlib import Path

from local_scaffold.reports import validate_child
from tests.conftest import SOURCE, payload, snapshots, source_python
from tests.test_atomic_publication import actual_strace as actual_strace
from tests.test_environment_failures import missing_tool_python as missing_tool_python


def test_public_metadata_import_failure_preserves_native_unavailability(
    root: Path, missing_tool_python: Path
) -> None:
    """A genuine trace-only interpreter cannot import the actual metadata producer."""
    before = snapshots(root)
    result = subprocess.run(
        source_python(
            str(SOURCE / "tools/check_repository_metadata.py"),
            "--root",
            str(root),
            "--json",
            executable=str(missing_tool_python),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    report = validate_child(payload(result, 3), "repository_metadata", result.returncode)
    assert report["reasons"] == [
        {
            "code": "tool_unavailable",
            "location": None,
            "detail": "Required local infrastructure condition failed: tool_unavailable.",
        }
    ]
    assert not report["checks"]
    assert snapshots(root) == before


def test_public_preflight_cleanup_denial_preserves_completed_prefix(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """Real EPERM after the second reaped producer keeps the first actual success."""
    before = snapshots(root)
    trace = tmp_path / "actual_public_second_cleanup_EPERM.native-trace"
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-o",
            str(trace),
            "-e",
            "trace=kill,wait4",
            "-e",
            "inject=kill:error=EPERM:when=2",
            *source_python(str(SOURCE / "tools/preflight.py"), "--root", str(root), "--json"),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    report = validate_child(payload(result, 3), "preflight", result.returncode)
    assert report["checks"][0] == {
        "role": "repository_metadata",
        "status": "passed",
        "exit_code": 0,
        "reason_codes": [],
    }
    assert report["checks"][1] == {
        "role": "source_provenance",
        "status": "refused",
        "exit_code": 2,
        "reason_codes": ["unexpected_fault"],
    }
    assert len(report["checks"]) == 18
    assert all(
        check["status"] == "not_run" and check["exit_code"] is None
        for check in report["checks"][2:]
    )
    assert [reason["code"] for reason in report["reasons"]] == [
        "unexpected_fault",
        *(["required_not_run"] * 16),
    ]
    calls = trace.read_bytes().splitlines()
    injected = [line for line in calls if b"INJECTED" in line]
    assert len(injected) == 1 and b"EPERM" in injected[0]
    matched = re.search(rb"kill\(-([0-9]+), SIGTERM\)", injected[0])
    assert matched is not None
    pid = matched.group(1)
    assert any(
        line.startswith(b"wait4(" + pid + b",")
        and b"WEXITSTATUS(s) == 0" in line
        and line.endswith(b"= " + pid)
        for line in calls
    )
    assert not Path("/proc/" + pid.decode()).exists()
    assert snapshots(root) == before


def test_public_preflight_interrole_signal_preserves_completed_role(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """Actual SIGTERM after the first recorded role retains every later not_run outcome."""
    before = snapshots(root)
    marker = tmp_path / "actual-interrole-signal.json"
    trace = tmp_path / "actual-interrole-SIGTERM.native-trace"
    program = '''import ast,json,os,runpy,signal,sys
from pathlib import Path
from types import CodeType
sys.path.insert(0,sys.argv[1])
from local_scaffold.orchestration import run_plan
source=Path(run_plan.__code__.co_filename)
function=next(node for node in ast.parse(source.read_bytes()).body if isinstance(node,ast.FunctionDef) and node.name=='run_plan')
loop=function.body[-1]
assert isinstance(loop,ast.For)
aggregation=loop.body[-1]
assert isinstance(aggregation,ast.Try)
pause_line=aggregation.body[0].lineno
assert isinstance(aggregation.body[0],ast.For)
marker=Path(sys.argv[3])
tool_id=3
assert sys.monitoring.get_tool(tool_id) is None
def interrupt(code: CodeType,line: int) -> None:
    """Interrupt the owned caller after its current role is already recorded."""
    if code is run_plan.__code__ and line==pause_line:
        sys.monitoring.set_local_events(tool_id,code,0)
        marker.write_text(json.dumps({'pid':os.getpid(),'line':line,'source':str(source)}))
        os.kill(os.getpid(),signal.SIGTERM)
sys.monitoring.use_tool_id(tool_id,'owned-interrole-signal')
sys.monitoring.register_callback(tool_id,sys.monitoring.events.LINE,interrupt)
sys.monitoring.set_local_events(tool_id,run_plan.__code__,sys.monitoring.events.LINE)
try:
    sys.argv=[str(Path(sys.argv[1])/'preflight.py'),'--root',sys.argv[2],'--json']
    runpy.run_path(sys.argv[0],run_name='__main__')
finally:
    sys.monitoring.set_local_events(tool_id,run_plan.__code__,0)
    sys.monitoring.register_callback(tool_id,sys.monitoring.events.LINE,None)
    sys.monitoring.free_tool_id(tool_id)
'''

    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-o",
            str(trace),
            "-e",
            "trace=kill,wait4",
            *source_python("-I", "-c", program, str(SOURCE / "tools"), str(root), str(marker)),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    report = validate_child(payload(result, 3), "preflight", result.returncode)
    assert report["checks"][0] == {
        "role": "repository_metadata",
        "status": "passed",
        "exit_code": 0,
        "reason_codes": [],
    }
    assert len(report["checks"]) == 18
    assert all(
        check["status"] == "not_run" and check["exit_code"] is None
        for check in report["checks"][1:]
    )
    assert [reason["code"] for reason in report["reasons"]] == ["interrupted"]
    observed = json.loads(marker.read_text())
    assert Path(observed["source"]) == SOURCE / "tools/local_scaffold/orchestration.py"
    pid = str(observed["pid"]).encode()
    calls = trace.read_bytes().splitlines()
    assert b"kill(" + pid + b", SIGTERM) = 0" in [b" ".join(line.split()) for line in calls]
    assert any(b"SIGTERM" in line and b"si_pid=" + pid in line for line in calls)
    assert any(b"WEXITSTATUS(s) == 0" in line for line in calls)
    assert not Path("/proc/" + pid.decode()).exists()
    assert snapshots(root) == before


def test_actual_full_diagnostic_budget_interruption_preserves_exit(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """Retain real interruption precedence after all allowed diagnostics are recorded."""
    for index in range(260):
        (root / f"unlicensed_{index:03d}.txt").write_text("no native header\n")
    before = snapshots(root)
    marker = tmp_path / "actual-full-budget-interruption.json"
    trace = tmp_path / "actual-full-budget-interruption.native-trace"
    program = '''import ast,json,os,runpy,signal,sys
from pathlib import Path
from types import CodeType
sys.path.insert(0,sys.argv[1])
from local_scaffold.reports import Report
source=Path(Report.add.__code__.co_filename)
klass=next(node for node in ast.parse(source.read_bytes()).body if isinstance(node,ast.ClassDef) and node.name=='Report')
method=next(node for node in klass.body if isinstance(node,ast.FunctionDef) and node.name=='add')
boundary=next(node.body[0].lineno for node in method.body if isinstance(node,ast.If) and isinstance(node.test,ast.Compare) and len(node.test.ops)==1 and isinstance(node.test.ops[0],ast.Eq) and isinstance(node.test.comparators[0],ast.Constant) and node.test.comparators[0].value==256)
marker=Path(sys.argv[3])
tool_id=3
assert sys.monitoring.get_tool(tool_id) is None
def interrupt(code: CodeType,line: int) -> None:
    """Interrupt once after the real report records its final allowed reason."""
    if code is Report.add.__code__ and line==boundary:
        sys.monitoring.set_local_events(tool_id,code,0)
        marker.write_text(json.dumps({'pid':os.getpid(),'source':str(source),'line':line}))
        os.kill(os.getpid(),signal.SIGTERM)
sys.monitoring.use_tool_id(tool_id,'owned-full-budget-interruption')
sys.monitoring.register_callback(tool_id,sys.monitoring.events.LINE,interrupt)
sys.monitoring.set_local_events(tool_id,Report.add.__code__,sys.monitoring.events.LINE)
try:
    sys.argv=[str(Path(sys.argv[1])/'check_source_provenance.py'),'--root',sys.argv[2],'--json']
    runpy.run_path(sys.argv[0],run_name='__main__')
finally:
    sys.monitoring.set_local_events(tool_id,Report.add.__code__,0)
    sys.monitoring.register_callback(tool_id,sys.monitoring.events.LINE,None)
    sys.monitoring.free_tool_id(tool_id)
'''
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-o",
            str(trace),
            "-e",
            "trace=kill,rt_sigaction,exit_group",
            *source_python("-I", "-c", program, str(SOURCE / "tools"), str(root), str(marker)),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    report = validate_child(payload(result, 3), "source_provenance", result.returncode)
    reasons = report["reasons"]
    assert isinstance(reasons, list) and len(reasons) == 256
    assert isinstance(reasons[-1], dict)
    assert reasons[-1]["code"] == "diagnostic_budget_exceeded"
    observed = json.loads(marker.read_bytes())
    assert Path(observed["source"]) == SOURCE / "tools/local_scaffold/reports.py"
    calls = trace.read_bytes().splitlines()
    assert ("kill(" + str(observed["pid"]) + ", SIGTERM) = 0").encode() in [
        b" ".join(line.split()) for line in calls
    ]
    assert any(
        b"SIGTERM" in line and b"si_pid=" + str(observed["pid"]).encode() in line for line in calls
    )
    assert any(line.startswith(b"exit_group(3)") for line in calls)
    assert snapshots(root) == before
