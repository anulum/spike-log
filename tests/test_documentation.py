# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Validate actual public pages, native source documentation and strict rendering."""

import json
import os
import signal
import subprocess
import sys
import time
from html.parser import HTMLParser
from pathlib import Path

import pytest

from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python
from tests.test_atomic_publication import actual_strace as actual_strace


class DialogNames(HTMLParser):
    """Inspect dialog names and search status in original native HTML output."""

    def __init__(self) -> None:
        """Collect labels from one independent generated public page."""
        super().__init__()
        self.names: list[str | None] = []
        self.search_statuses: list[tuple[str | None, str | None, str | None]] = []
        self.header_controls: list[tuple[str | None, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Record actual dialog names and the search status's live properties."""
        attributes = dict(attrs)
        if tag == "label" and "md-header__button" in (attributes.get("class") or "").split():
            self.header_controls.append((attributes.get("for"), attributes.get("aria-label")))
        if attributes.get("role") == "dialog":
            self.names.append(attributes.get("aria-label"))
        if "md-search-result__meta" in (attributes.get("class") or "").split():
            self.search_statuses.append(
                (
                    attributes.get("role"),
                    attributes.get("aria-live"),
                    attributes.get("aria-atomic"),
                )
            )


@pytest.mark.parametrize(
    "case",
    [
        "file-link",
        "reference-file",
        "reference-anchor",
        "reference-image",
        "html-link",
        "anchor",
        "outside",
        "visible",
        "api",
        "release",
        "private",
        "asset",
        "docstring",
        "syntax",
        "funding",
        "renderer",
        "rendered-broken",
        "cache-link",
        "interface-docstring",
    ],
)
def test_public_documentation_refusals(root: Path, case: str) -> None:
    """Supply concrete invalid public input and observe the genuine guard/tool."""
    path = root / "README.md"
    text = path.read_text()
    additions = {
        "file-link": "[missing](missing.md)",
        "reference-file": "[missing][target]\n\n[target]: missing-reference.md",
        "reference-anchor": "[missing][target]\n\n[target]: README.md#missing-reference",
        "reference-image": "![missing][target]\n\n[target]: docs/assets/missing.png",
        "html-link": '<a href="missing-html-link.md">missing</a>',
        "anchor": "[anchor](README.md#does-not-exist)",
        "outside": "[outside](../../private.md)",
        "visible": "SPDX-License-Identifier" + ": AGPL-3.0-or-later",
        "api": "spike-log record is implemented",
        "release": "https://doi.org/10.1234/false",
        "private": "[private](.coordination/private.md)",
    }
    if case in additions:
        path.write_text(text + "\n" + additions[case] + "\n")
    elif case == "asset":
        (root / "docs/assets/anulum_logo.png").write_bytes(b"wrong actual logo")
    elif case in ("docstring", "syntax"):
        source = root / "tools/check_repository_metadata.py"
        source.write_text(
            source.read_text() + "\ndef undocumented() -> None:\n    return None\n"
            if case == "docstring"
            else "not valid python )\n"
        )
    elif case == "funding":
        funding = root / ".github/FUNDING.yml"
        funding.write_text(funding.read_text().replace("github: anulum", "github: foreign"))
    elif case == "renderer":
        (root / "mkdocs.yml").write_text("plugins: [not-installed]\n")
    elif case == "cache-link":
        import shutil

        shutil.rmtree(root / ".tool-cache")
        (root / ".tool-cache").symlink_to(root / "docs", target_is_directory=True)
    elif case == "interface-docstring":
        source = root / "tools/received_interface.pyi"
        source.write_text(
            (root / "tools/check_repository_metadata.py").read_text().split('"""', 1)[0]
            + '\n"""Received interface under inspection."""\n'
            + "def observed_digest(data: bytes) -> str:\n    ...\n"
        )
    else:
        (root / "docs/index.md").write_text(
            (root / "docs/index.md").read_text() + "\n::: actual_missing_reference_module\n"
        )
    payload(run_guard("documentation", root), 2)


def test_real_renderer_and_empty_roster(root: Path) -> None:
    """Complete renderer acceptance includes honest empty support state."""
    before = snapshots(root)
    a = run_guard("documentation", root)
    b = run_guard("documentation", root)
    payload(a, 0)
    assert a.stdout == b.stdout
    assert snapshots(root) == before


@pytest.mark.parametrize("fault", ["missing", "modified", "malicious", "extra", "link"])
def test_received_template_refusal_prevents_execution(root: Path, fault: str) -> None:
    """Refuse actual unknown or changed executable overrides before native rendering."""
    template = root / "overrides/main.html"
    marker = root.parent / "received-template-was-executed"
    received = "{{ cycler.__init__.__globals__.os.system(" + repr("touch " + str(marker)) + ") }}"
    if fault == "missing":
        template.unlink()
    elif fault == "modified":
        template.write_text(template.read_text() + "\nReceived extra template content.\n")
    elif fault == "malicious":
        template.write_text(template.read_text() + "\n" + received + "\n")
    elif fault == "extra":
        (template.parent / "base.html").write_text(received)
    else:
        template.unlink()
        template.symlink_to(root / "docs/index.md")
    before = snapshots(root)
    value = payload(run_guard("documentation", root), 2)
    assert value["reasons"]
    assert not marker.exists()
    assert snapshots(root) == before
    assert not any(
        p.name.startswith(("renderer-", "docs-")) for p in (root / ".tool-cache").iterdir()
    )


def test_late_received_template_and_config_changes_cannot_execute(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """Observe complete captured config before the delayed genuine Python renderer exec."""
    cache = root / ".tool-cache"
    marker = root.parent / "late-received-template-was-executed"
    trace = tmp_path / "actual-captured-documentation-config.native-trace"
    process = subprocess.Popen(
        [
            str(actual_strace),
            "-f",
            "--seccomp-bpf",
            "--kill-on-exit",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-P",
            str(sys.executable),
            "-e",
            "trace=execve",
            "-e",
            "inject=execve:delay_enter=2s",
            *source_python(
                str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"
            ),
        ],
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            lines = trace.read_text().splitlines() if trace.exists() else []
            captured_files = list(cache.glob("renderer-*/mkdocs.yml"))
            if captured_files:
                assert len(captured_files) == 1
                captured = captured_files[0]
                captured_text = captured.read_text()
                if not captured_text.endswith("\n") or "docs_dir: " not in captured_text:
                    time.sleep(0.001)
                    continue
                assert captured.parent.parent == cache and not captured.is_symlink()
                assert str(root / "docs") in captured_text and str(root / "tools") in captured_text
                template = root / "overrides/main.html"
                assert (
                    captured.parent / "overrides/main.html"
                ).read_bytes() == template.read_bytes()
                template.write_text(
                    template.read_text()
                    + "\n{{ cycler.__init__.__globals__.os.system("
                    + repr("touch " + str(marker))
                    + ") }}\n"
                )
                (root / "mkdocs.yml").write_text("plugins: [received-uninstalled-plugin]\n")
                break
            assert process.poll() is None, lines
            time.sleep(0.001)
        else:
            raise AssertionError(
                "Actual complete captured renderer configuration was not observed."
            )
        before = snapshots(root)
        stdout, stderr = process.communicate(timeout=30)
        payload(subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 0)
        assert not marker.exists()
        assert snapshots(root) == before
        raw = trace.read_bytes()
        assert raw.count(b"execve(") >= 2 and b"DELAYED" in raw
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    assert not any(p.name.startswith(("renderer-", "docs-")) for p in cache.iterdir())


def test_real_renderer_excludes_private_documents_and_assets(root: Path, tmp_path: Path) -> None:
    """Original native rendering keeps private pages, assets and search content out."""
    private = root / "docs/internal/rendering-custody"
    private.mkdir(parents=True, exist_ok=True)
    marker = "Owner-private rendering sentinel"
    (private / "owner-review.md").write_text(
        (root / "docs/index.md").read_text().split("-->", 1)[0]
        + "-->\n\n# Private owner review\n\n"
        + marker
        + "\n"
    )
    (private / "retained-source.bin").write_bytes(b"actual private retained source bytes")
    before = snapshots(root)
    payload(run_guard("documentation", root), 0)
    output = tmp_path / "actual-public-documentation"
    rendered = subprocess.run(
        source_python(
            "-m",
            "mkdocs",
            "build",
            "--strict",
            "--config-file",
            str(root / "mkdocs.yml"),
            "--site-dir",
            str(output),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    assert rendered.returncode == 0, rendered.stderr.decode()
    assert not (output / "internal").exists()
    for name in (
        "index.html",
        "404.html",
        "ARCHITECTURE/index.html",
        "validation-tooling/index.html",
        "THREAT_MODEL/index.html",
        "adr/0001-repository-boundary/index.html",
    ):
        assert (output / name).is_file()
        dialogs = DialogNames()
        dialogs.feed((output / name).read_text())
        assert dialogs.names == ["Search"], name
        assert dialogs.search_statuses == [("status", "polite", "true")], name
        assert dialogs.header_controls == [("__drawer", "Navigation"), ("__search", "Search")], name
    search = json.loads((output / "search/search_index.json").read_bytes())
    assert all(not item["location"].startswith("internal/") for item in search["docs"])
    assert marker not in (output / "search/search_index.json").read_text()
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "destination",
    ["#spike-log", "<README.md#spike-log>", "docs/assets/anulum_logo.png#xywh=0,0,10,10"],
)
def test_real_local_anchors_and_media_fragments(root: Path, destination: str) -> None:
    """Accept genuine same-page anchors and non-Markdown media destinations."""
    path = root / "README.md"
    path.write_text(path.read_text() + "\n[Observed local target](" + destination + ")\n")
    before = snapshots(root)
    payload(run_guard("documentation", root), 0)
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "example",
    [
        "`[example](absent-example.md)`",
        "```md\n[example](absent-example.md)\n```",
        "<!-- [example](absent-example.md) -->",
    ],
    ids=["inline-code", "fenced-code", "comment"],
)
def test_documentation_examples_do_not_create_links(root: Path, example: str) -> None:
    """Accept literal examples and comments without treating their text as links."""
    path = root / "README.md"
    path.write_text(path.read_text() + "\n" + example + "\n")
    before = snapshots(root)
    payload(run_guard("documentation", root), 0)
    assert snapshots(root) == before


@pytest.mark.parametrize("tag,expected", [("a", 0), ("span", 2)])
def test_actual_legacy_named_anchor_elements(root: Path, tag: str, expected: int) -> None:
    """Only actual legacy a-name elements supply named fragment targets."""
    path = root / "README.md"
    path.write_text(
        path.read_text()
        + f'\n<{tag} name="ordinary-name">Named element</{tag}>\n'
        + "\n[Named element](#ordinary-name)\n"
    )
    before = snapshots(root)
    report = payload(run_guard("documentation", root), expected)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    if expected:
        assert any(
            isinstance(reason, dict) and reason["code"] == "documentation.local-link"
            for reason in reasons
        )
    assert snapshots(root) == before


@pytest.mark.parametrize(
    "source,link,accepted",
    [
        ("README.md", "[API](docs/validation-tooling.md#local_scaffold.cli.main)", False),
        ("README.md", "[Overview](docs/index.md#spike-log)", True),
        ("docs/index.md", "[API](validation-tooling.md#local_scaffold.cli.main)", True),
        ("docs/validation-tooling.md", "[API](#local_scaffold.cli.main)", True),
        (
            "docs/adr/0001-repository-boundary.md",
            "[API](../validation-tooling.md#local_scaffold.workflows.WorkflowSnapshot)",
            True,
        ),
        (
            "docs/index.md",
            "[API][target]\n\n[target]: validation-tooling.md#local_scaffold%2Ecli%2Emain",
            True,
        ),
        (
            "docs/index.md",
            "[API](validation-tooling.md#local_scaffold.cli.absent_method)",
            False,
        ),
        (
            "README.md",
            "[API](docs/validation-tooling.md#local_scaffold.cli.absent_method)",
            False,
        ),
        ("docs/index.md", "[Omitted page](internal/omitted.md#omitted)", False),
    ],
)
def test_actual_generated_api_fragment_targets(
    root: Path, source: str, link: str, accepted: bool
) -> None:
    """Accept real generated API anchors and refuse absent ones through the CLI."""
    omitted = root / "docs/internal/omitted.md"
    omitted.parent.mkdir(parents=True, exist_ok=True)
    omitted.write_text(
        (root / "docs/index.md").read_text().split("-->", 1)[0] + "-->\n\n# Omitted\n"
    )
    path = root / source
    path.write_text(path.read_text() + "\n" + link + "\n")
    before = snapshots(root)
    report = payload(run_guard("documentation", root), 0 if accepted else 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    if not accepted:
        assert any(
            isinstance(reason, dict) and reason["code"] == "documentation.local-link"
            for reason in reasons
        )
    assert snapshots(root) == before


def test_actual_documentation_interruption_cleans_owned_output(root: Path) -> None:
    """Interrupt the real public renderer operation and preserve its owned inputs."""
    before = snapshots(root)
    process = subprocess.Popen(
        source_python(str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"),
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 10
        while not list((root / ".tool-cache").glob("docs-*")):
            assert process.poll() is None, "Renderer exited before the interruption boundary."
            assert time.monotonic() < deadline
            time.sleep(0.01)
        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    value = payload(
        subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 3
    )
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert any(isinstance(reason, dict) and reason["code"] == "interrupted" for reason in reasons)
    assert not list((root / ".tool-cache").glob("docs-*"))
    assert snapshots(root) == before


@pytest.mark.parametrize("signum", ["SIGTERM", "SIGINT"])
def test_actual_event_loop_startup_interruption_has_no_resource_warnings(
    root: Path, tmp_path: Path, actual_strace: Path, signum: str
) -> None:
    """A real signal at native loop socket creation leaves no output or warnings."""
    before = snapshots(root)
    trace = tmp_path / (signum + "-loop-startup.native-trace")
    result = subprocess.run(
        [
            str(actual_strace),
            "-qq",
            "-o",
            str(trace),
            "-e",
            "trace=socketpair,rt_sigprocmask,execve,close",
            "-e",
            "inject=socketpair:signal=" + signum + ":when=1",
            *source_python(
                str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"
            ),
        ],
        cwd=SOURCE,
        capture_output=True,
        timeout=30,
    )
    value = payload(result, 3)
    assert value["reasons"] == [
        {
            "code": "interrupted",
            "location": None,
            "detail": "Required local infrastructure condition failed: interrupted.",
        }
    ]
    raw = trace.read_bytes()
    assert b"socketpair(" in raw and signum.encode() in raw
    assert b"mkdocs" not in raw
    assert snapshots(root) == before
    assert not list((root / ".tool-cache").glob("docs-*"))


@pytest.mark.parametrize("fault", ["missing-index", "private-directory", "private-symlink"])
def test_actual_renderer_success_with_missing_output_is_refused(
    root: Path, fault: str, tmp_path: Path, actual_strace: Path
) -> None:
    """Observe actual index close and refuse changed output after native success."""
    cache = root / ".tool-cache"
    before = snapshots(root)
    trace = tmp_path / (fault + "-actual-renderer-output.native-trace")
    process = subprocess.Popen(
        [
            str(actual_strace),
            "-f",
            "--seccomp-bpf",
            "--kill-on-exit",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-e",
            "trace=execve,close,exit_group",
            "-e",
            "inject=exit_group:delay_enter=2s",
            *source_python(
                str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"
            ),
        ],
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            lines = trace.read_text().splitlines() if trace.exists() else []
            closes = [
                line
                for line in lines
                if "close(" in line
                and str(cache) + "/docs-" in line
                and "/index.html>" in line
                and "= 0" in line
            ]
            if closes:
                renderer_pid = int(closes[0].split()[0])
                index = Path(closes[0].split("<", 1)[1].split(">", 1)[0])
                directory = index.parent
                assert directory.parent == cache and not directory.is_symlink()
                assert index.is_file() and index.stat().st_size > 0
                if fault == "missing-index":
                    index.unlink()
                elif fault == "private-directory":
                    (directory / "internal").mkdir()
                    (directory / "internal/retained-owner-record.txt").write_bytes(
                        b"actual retained private output bytes"
                    )
                else:
                    (directory / "internal").symlink_to(directory / "absent-private-target")
                break
            assert process.poll() is None, lines
            time.sleep(0.001)
        else:
            raise AssertionError("Actual renderer index close was not observed.")
        stdout, stderr = process.communicate(timeout=15)
        value = payload(
            subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 2
        )
        code = (
            "documentation.renderer-failure"
            if fault == "missing-index"
            else "documentation.private-plan"
        )
        assert value["reasons"] == [
            {
                "code": code,
                "location": "docs/index.md" if fault == "missing-index" else "docs/internal",
                "detail": "Required local infrastructure condition failed: " + code + ".",
            }
        ]
        native_lines = trace.read_text().splitlines()
        assert any(
            line.startswith(str(renderer_pid) + " ")
            and "execve(" in line
            and '"mkdocs", "build"' in line
            for line in native_lines
        )
        assert any(
            line.startswith(str(renderer_pid) + " ") and "+++ exited with 0 +++" in line
            for line in native_lines
        )
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    assert snapshots(root) == before
    assert not any(path.name.startswith("docs-") for path in cache.iterdir())


def test_real_cache_link_after_configuration_read_is_refused(
    root: Path, tmp_path: Path, actual_strace: Path
) -> None:
    """Replace actual cache after native config close, before its delayed lstat."""
    cache = root / ".tool-cache"
    configuration = root / "mkdocs.yml"
    held = root.parent / "actual-retained-documentation-cache"
    assert not held.exists()
    before = snapshots(root)
    trace = tmp_path / "actual-late-documentation-cache.native-trace"
    process = subprocess.Popen(
        [
            str(actual_strace),
            "-f",
            "--kill-on-exit",
            "-yy",
            "-s",
            "4096",
            "-o",
            str(trace),
            "-P",
            str(cache),
            "-P",
            str(configuration),
            "-e",
            "trace=newfstatat,lstat,openat,close",
            "-e",
            "inject=newfstatat:delay_enter=1s",
            "-e",
            "inject=lstat:delay_enter=1s",
            *source_python(
                str(SOURCE / "tools/check_documentation.py"), "--root", str(root), "--json"
            ),
        ],
        cwd=SOURCE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            lines = trace.read_text().splitlines() if trace.exists() else []
            if any(
                "close(" in line and str(configuration) in line and "= 0" in line for line in lines
            ):
                cache.rename(held)
                cache.symlink_to(held, target_is_directory=True)
                break
            assert process.poll() is None, lines
            time.sleep(0.001)
        else:
            raise AssertionError("Actual original renderer configuration read was not observed.")
        stdout, stderr = process.communicate(timeout=25)
        value = payload(
            subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr), 2
        )
        assert value["reasons"] == [
            {
                "code": "repository_inventory.symlink-entry",
                "location": ".tool-cache",
                "detail": "Required local infrastructure condition failed: "
                "repository_inventory.symlink-entry.",
            }
        ]
        raw = trace.read_bytes()
        assert b"DELAYED" in raw and os.fsencode(configuration) in raw
        assert os.fsencode(cache) in raw and b"S_IFLNK" in raw
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        if held.exists():
            cache.unlink()
            held.rename(cache)
    assert snapshots(root) == before
    assert cache.is_dir() and not cache.is_symlink() and not held.exists()


@pytest.mark.parametrize("operation", ["record", "replay", "inspect", "verify", "slice"])
def test_each_planned_domain_operation_cannot_claim_implementation(
    root: Path, operation: str
) -> None:
    """Refuse false support claims at the real public documentation boundary."""
    path = root / "README.md"
    path.write_text(path.read_text() + "\nspike-log " + operation + " is implemented\n")
    before = snapshots(root)
    value = payload(run_guard("documentation", root), 2)
    reasons = value["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "documentation.fake-api"
        for reason in reasons
    )
    assert snapshots(root) == before
