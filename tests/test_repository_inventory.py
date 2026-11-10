# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check all required entries and real exclusive-write/recovery behaviour."""

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.conftest import SOURCE, change, payload, run_guard, snapshots, source_python

REQUIRED_PATHS = """.editorconfig .gitattributes .github/CODEOWNERS .github/FUNDING.yml .github/ISSUE_TEMPLATE/bug_report.yml .github/ISSUE_TEMPLATE/config.yml .github/ISSUE_TEMPLATE/feature_request.yml .github/dependabot.yml .github/pull_request_template.md .github/workflows/ci.yml .github/workflows/codeql.yml .github/workflows/docs.yml .github/workflows/pre-commit.yml .github/workflows/sbom.yml .github/workflows/scorecard.yml .github/workflows/security-audit.yml .gitignore .pre-commit-config.yaml .zenodo.json ARCHITECTURE.md CHANGELOG.md CITATION.cff CODE_OF_CONDUCT.md CONTRIBUTING.md CONTRIBUTORS.md GOVERNANCE.md LICENSE LICENSES Makefile NOTICE.md README.md REUSE.toml ROADMAP.md SECURITY.md SUPPORT.md VALIDATION.md docs/ARCHITECTURE.md docs/THREAT_MODEL.md docs/adr/0001-repository-boundary.md pyproject.toml requirements-dev.txt tests tools/preflight.py repository-domain.json schemas/repository-domain.schema.json capability-inventory.json mkdocs.yml tools/check_repository_metadata.py tools/check_source_provenance.py tools/check_workflow_policy.py tools/check_dependency_alignment.py tools/check_documentation.py tools/check_repository_inventory.py docs/assets/anulum_logo_company.jpg docs/assets/anulum_logo.png docs/assets/fortis_studio_logo.jpg repository-domain.json.license schemas/repository-domain.schema.json.license capability-inventory.json.license .zenodo.json.license requirements-dev.in dependency-provenance.json dependency-provenance.json.license docs/index.md docs/validation-tooling.md tests/test_repository_metadata.py tests/test_source_provenance.py tests/test_workflow_policy.py tests/test_dependency_alignment.py tests/test_documentation.py tests/test_repository_inventory.py tests/test_preflight.py workflow-policy.json workflow-policy.json.license .make/quality.mk .make/environment.mk .make/fixtures.mk tools/reproduce_dependency_provenance.py""".split()


@pytest.mark.parametrize("name", REQUIRED_PATHS)
def test_every_required_path(root: Path, name: str) -> None:
    """Remove each distinct actual obligation and observe native unavailability."""
    path = root / name
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    value = payload(run_guard("repository_inventory", root), 3)
    assert name.encode() in json.dumps(value).encode()


@pytest.mark.parametrize(
    "name",
    [
        ".coordination",
        ".env",
        "04_ARCANE_SAPIENCE",
        "AGENTS.md",
        "BACKUP",
        "CLAUDE.md",
        "CODEX.md",
        "GEMINI.md",
        "GROK.md",
        "KIMI.md",
    ],
)
def test_forbidden_trees(root: Path, name: str) -> None:
    """Ignored but prohibited state still refuses the actual complete source tree."""
    (root / name).mkdir()
    value = payload(run_guard("repository_inventory", root), 2)
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict)
        and isinstance(reason["code"], str)
        and reason["code"].startswith("repository_inventory.forbidden-tree.")
        and reason["location"] == name
        for reason in reasons
    )


@pytest.mark.parametrize(
    "case",
    [
        "kind",
        "link",
        "fifo",
        "private-tracked",
        "packaged",
        "binary",
        "source-hash",
        "identity",
        "depth",
        "entries",
        "file-size",
        "cache-kind",
        "cache-link",
    ],
)
def test_real_tree_faults(root: Path, case: str) -> None:
    """Create actual hostile tree shapes, raw drift and Git index state."""
    if case == "kind":
        shutil.rmtree(root / "LICENSES")
        (root / "LICENSES").write_text("wrong kind")
    elif case == "link":
        (root / "escape").symlink_to(root.parent)
    elif case == "fifo":
        os.mkfifo(root / "pipe")
    elif case == "private-tracked":
        path = root / "docs/internal/private.txt"
        path.parent.mkdir(exist_ok=True)
        path.write_text("private fixture")
        subprocess.run(
            ["git", "-C", str(root), "add", "-f", "docs/internal/private.txt"], check=True
        )
        indexed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "-z"],
            capture_output=True,
            timeout=10,
            check=True,
        )
        assert indexed.stdout == b"docs/internal/private.txt\0"
    elif case == "packaged":
        path = root / "pyproject.toml"
        original = path.read_text()
        assert original.count('path = "src/spike_log/py.typed"') == 1
        path.write_text(
            original.replace('path = "src/spike_log/py.typed"', 'path = "docs/internal"')
        )
    elif case == "binary":
        (root / "unprovenanced.png").write_bytes(b"actual unprovenanced binary")
    elif case == "source-hash":
        path = root / "repository-domain.json"
        path.write_bytes(path.read_bytes() + b"\n")
    elif case == "identity":
        change(root, "capability-inventory.json", ("claims",), ["false qualification"])
    elif case == "depth":
        (root / ("/".join("deep" for _ in range(33)))).mkdir(parents=True)
    elif case == "entries":
        directory = root / "many"
        directory.mkdir()
        for i in range(4097):
            (directory / str(i)).touch()
    elif case == "file-size":
        with (root / "large.txt").open("wb") as file:
            file.truncate(16777217)
    else:
        shutil.rmtree(root / ".tool-cache")
        if case == "cache-kind":
            (root / ".tool-cache").write_text("wrong ignored kind")
        else:
            (root / ".tool-cache").symlink_to(root / "docs", target_is_directory=True)
    value = payload(run_guard("repository_inventory", root), 2)
    expected = {
        "kind": "repository_inventory.wrong-kind",
        "link": "repository_inventory.symlink-entry",
        "fifo": "repository_inventory.special-file",
        "private-tracked": "repository_inventory.private-tracked",
        "packaged": "repository_inventory.private-packaged",
        "binary": "repository_inventory.unexpected-binary",
        "source-hash": "repository_inventory.source-hash",
        "identity": "repository_inventory.inventory-identity",
        "depth": "resource_limit",
        "entries": "resource_limit",
        "file-size": "resource_limit",
        "cache-kind": "repository_inventory.wrong-kind",
        "cache-link": "repository_inventory.symlink-entry",
    }
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason.get("code") == expected[case] for reason in reasons
    )


def test_inventory_goldens_and_readonly(root: Path) -> None:
    """Compare independently specified golden state and repeated verification."""
    metadata = (root / "repository-domain.json").read_bytes()
    expected = {
        "repository_name": "SPIKE-LOG",
        "lifecycle": "local_scaffold",
        "evidence_maturity": "architecture_only",
        "capabilities": [],
        "claims": [],
        "qualified_owned_schema_ids": [],
        "source_metadata": {
            "path": "repository-domain.json",
            "sha256": hashlib.sha256(metadata).hexdigest(),
        },
    }
    before = snapshots(root)
    a = run_guard("repository_inventory", root)
    b = run_guard("repository_inventory", root)
    payload(a, 0)
    assert a.stdout == b.stdout
    assert snapshots(root) == before
    result = run_guard("repository_inventory", root, "--mode", "generate", "--output", "new.json")
    assert result.returncode == 0
    assert json.loads(result.stdout)["scope"] == "inventory_generate"
    assert (root / "new.json").read_bytes() == (
        json.dumps(expected, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode()
    original = (root / "new.json").read_bytes()
    again = run_guard("repository_inventory", root, "--mode", "generate", "--output", "new.json")
    assert again.returncode == 2
    assert (root / "new.json").read_bytes() == original


@pytest.mark.parametrize(
    "output", ["../outside.json", "/tmp/outside-private-sentinel.json", "missing/target.json"]
)
def test_output_boundaries(root: Path, output: str) -> None:
    """Outside and unavailable output destinations never expose private inputs."""
    result = run_guard("repository_inventory", root, "--mode", "generate", "--output", output)
    assert result.returncode == 2
    assert b"private-sentinel" not in result.stdout
    assert not list(root.glob(".spike-log-inventory-*"))


@pytest.mark.parametrize(
    "arguments", [("--mode", "generate"), ("--mode", "verify", "--output", "private-sentinel.json")]
)
def test_inventory_mode_and_destination_must_agree(root: Path, arguments: tuple[str, ...]) -> None:
    """Refuse missing generation destinations and ignored verification outputs."""
    before = snapshots(root)
    result = run_guard("repository_inventory", root, *arguments)
    payload(result, 4)
    assert b"private-sentinel" not in result.stdout
    assert snapshots(root) == before
    assert not (root / "private-sentinel.json").exists()


def test_real_write_limit(root: Path) -> None:
    """An actual OS file-size limit causes recovery without a partial publication."""
    code = """import resource,runpy,sys,pathlib
prior=resource.getrlimit(resource.RLIMIT_FSIZE)
resource.setrlimit(resource.RLIMIT_FSIZE,(128,prior[1]))
sys.argv=sys.argv[1:]
sys.path.insert(0,str(pathlib.Path(sys.argv[0]).parent))
try:
    runpy.run_path(sys.argv[0],run_name='__main__')
finally:
    resource.setrlimit(resource.RLIMIT_FSIZE,prior)
"""
    result = subprocess.run(
        source_python(
            "-c",
            code,
            str(SOURCE / "tools/check_repository_inventory.py"),
            "--root",
            str(root),
            "--json",
            "--mode",
            "generate",
            "--output",
            "limited.json",
        ),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (root / "limited.json").exists()
    assert not list(root.glob(".spike-log-inventory-*"))


def test_permissions_and_symbolic_destination(root: Path) -> None:
    """Real permission denial and symbolic parent never damage outside state."""
    assert os.getuid() != 0
    directory = root / "locked"
    directory.mkdir()
    directory.chmod(0o500)
    try:
        assert (
            run_guard(
                "repository_inventory", root, "--mode", "generate", "--output", "locked/new.json"
            ).returncode
            == 2
        )
    finally:
        directory.chmod(0o700)
    (root / "linked").symlink_to(directory, target_is_directory=True)
    assert (
        run_guard(
            "repository_inventory", root, "--mode", "generate", "--output", "linked/new.json"
        ).returncode
        == 2
    )
    assert not list(directory.iterdir())


def test_actual_public_Git_index_is_accepted(root: Path) -> None:
    """The public inventory accepts genuine tracked public bytes without changing them."""
    subprocess.run(
        ["git", "-C", str(root), "add", "--", "README.md", "tools/check_repository_metadata.py"],
        capture_output=True,
        timeout=10,
        check=True,
    )
    before = snapshots(root)
    indexed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        capture_output=True,
        timeout=10,
        check=True,
    )
    assert indexed.stdout == b"README.md\0tools/check_repository_metadata.py\0"
    payload(run_guard("repository_inventory", root), 0)
    assert snapshots(root) == before
    after = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        capture_output=True,
        timeout=10,
        check=True,
    )
    assert after.stdout == indexed.stdout


@pytest.mark.parametrize("public", [False, True])
def test_private_working_identifiers_stay_outside_public_projection(
    root: Path, public: bool
) -> None:
    """Retain genuine ignored queue data while refusing the same public JSON content."""
    identifier = "-".join(("BL", "7"))
    name = "received.json" if public else "docs/internal/" + identifier + ".json"
    path = root / name
    path.parent.mkdir(exist_ok=True)
    body = json.dumps(
        {
            "workstream": identifier,
            "record": "_".join(("runtime", "metadata", "regressions", "whole", "r27")),
        }
    ).encode()
    path.write_bytes(body)
    ignored = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "--quiet", "--no-index", "--", name],
        capture_output=True,
        timeout=10,
    )
    assert ignored.returncode == (1 if public else 0)
    before = snapshots(root)
    value = payload(run_guard("repository_inventory", root), 2 if public else 0)
    assert ("policy_refusal" in str(value["reasons"])) is public
    assert path.read_bytes() == body and snapshots(root) == before
