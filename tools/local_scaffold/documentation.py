# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Inspect honest public scope, real links, native docstrings and strict rendering."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import markdown

from .bindings import DOCUMENTATION_FRAGMENT_HOOK_SHA256, DOCUMENTATION_TEMPLATE_SHA256
from .documentation_api import imports_supported
from .identity import SPDX_PREFIX, source_header
from .inputs import read_bytes, read_text, relative_path, yaml_object
from .inventory import owned_tree
from .policy import ASSETS, FUNDING, MAX_FILE, MKDOCS_SHA256
from .processes import run_process
from .production_names import check_text
from .reports import Fault, Report


class RenderedPage(HTMLParser):
    """Collect rendered anchors, link destinations and HTML character data.

    Attributes
    ----------
    anchors : set[str]
        Nonempty id/name anchors observed in native Markdown-rendered HTML.
    destinations : list[str]
        Actual link href and image src values from the rendered HTML, in document order.
    visible : list[str]
        Parsed HTML character data with comments excluded; CSS/browser visibility is not evaluated.
    """

    def __init__(self) -> None:
        """Initialise independent page observations for one actual renderer output."""
        super().__init__(convert_charrefs=True)
        self.anchors: set[str] = set()
        self.destinations: list[str] = []
        self.visible: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Retain real named anchors and link/image targets from rendered elements.

        Parameters
        ----------
        tag : str
            HTMLParser element tag; a and img elements supply href and src destinations.
        attrs : list[tuple[str, str | None]]
            Parsed attributes supplying named anchors and nonempty link/image destinations.
        """
        for key, value in attrs:
            if value and (key == "id" or (tag == "a" and key == "name")):
                self.anchors.add(value)
            if value and ((tag == "a" and key == "href") or (tag == "img" and key == "src")):
                self.destinations.append(value)

    def handle_data(self, data: str) -> None:
        """Record parsed HTML character data; HTML comments do not enter this callback.

        Parameters
        ----------
        data : str
            HTMLParser character data appended without evaluating CSS or browser visibility.
        """
        self.visible.append(data)


def page(text: str) -> RenderedPage:
    """Render maintained Markdown and parse its actual anchors, links and text.

    Parameters
    ----------
    text : str
        Maintained Markdown rendered with toc, fenced-code and table extensions.

    Returns
    -------
    RenderedPage
        Anchors, link/image destinations and character data from native HTML. Code examples
        and comments do not create link targets; browser visibility is not evaluated.
    """
    result = RenderedPage()
    result.feed(markdown.markdown(text, extensions=["toc", "fenced_code", "tables"]))
    return result


def rendered_fragments(output: Path, links: list[tuple[str, str, str]], report: Report) -> None:
    """Check doc-page fragments against their actual bounded rendered HTML.

    Parameters
    ----------
    output : Path
        Owned site output from the fixed renderer and accepted configuration.
    links : list[tuple[str, str, str]]
        Source location, docs-relative Markdown target and decoded fragment.
    report : Report
        Receives local-link refusals for absent built pages or anchors.

    Raises
    ------
    Fault
        Raised if generated HTML is unavailable, unsafe, oversized or invalid UTF-8.
    """
    from mkdocs.structure.files import File

    anchors: dict[str, set[str]] = {}
    for source, target, fragment in links:
        destination = File(target, None, str(output), use_directory_urls=True).dest_uri
        if destination not in anchors:
            if not relative_path(output, destination).is_file():
                report.add("documentation.local-link", source)
                continue
            rendered = RenderedPage()
            rendered.feed(read_text(output, destination, MAX_FILE))
            anchors[destination] = rendered.anchors
        if fragment not in anchors[destination]:
            report.add("documentation.local-link", source)


def native_documentation(root: Path, report: Report) -> None:
    """Require docstring presence on every maintained module, class and function.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives native-doc-gap reasons for undocumented maintained Python modules, classes and functions.

    Raises
    ------
    Fault
        Raised for invalid maintained Python syntax or unavailable/unbounded source input.
    """
    for name in owned_tree(root, report):
        if not name.endswith((".py", ".pyi")) or name.startswith("docs/internal/"):
            continue
        try:
            module = ast.parse(read_text(root, name))
        except SyntaxError as error:
            raise Fault("documentation.native-doc-gap", name) from error
        nodes = [
            module,
            *(
                node
                for node in ast.walk(module)
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            ),
        ]
        if any(not ast.get_docstring(node) for node in nodes):
            report.add("documentation.native-doc-gap", name)


def verify(root: Path, report: Report) -> None:
    """Validate public claims, local targets, assets and the real configured renderer.

    Parameters
    ----------
    root : Path
        Repository directory supplying bounded local inputs; it does not supply executable tool paths.
    report : Report
        Receives claim/link/asset/ownership/doc/renderer refusals, including any private rendered path.

    Raises
    ------
    Fault
        Raised for unavailable or unsafe inputs, cache symlinks, native process interruption/deadline or bounded resource failure.
    """
    files = owned_tree(root, report)
    built_links: list[tuple[str, str, str]] = []
    for name in files:
        if not name.endswith(".md") or name.startswith(("LICENSES/", "docs/internal/")):
            continue
        text = read_text(root, name)
        rendered = page(text)
        visible = " ".join(rendered.visible)
        check_text(visible, name, report)
        if (
            not text.startswith("<!--\n" + "\n".join(source_header(name)) + "\n-->")
            or SPDX_PREFIX in visible
        ):
            report.add("documentation.visible-provenance", name)
        if re.search(
            r"(?:\.coordination/|agentic-shared/|codex-[0-9a-f]|gpt-[0-9]|/home/|/media/)", text
        ):
            report.add("documentation.private-plan", name)
        if re.search(
            r"(?:pip install spike.log|spike-log (?:record|replay|inspect|verify|slice|create|build_index).*implemented)",
            text,
            re.IGNORECASE,
        ):
            report.add("documentation.fake-api", name)
        if not imports_supported(root, text):
            report.add("documentation.fake-api", name)
        if re.search(
            r"(?:\[!\[|doi\.org/10\.|api\.scorecard\.dev|pypi\.org/project/spike.log)",
            text,
            re.IGNORECASE,
        ):
            report.add("documentation.fake-release", name)
        for destination in rendered.destinations:
            url = urlsplit(destination)
            if url.scheme or url.netloc:
                continue
            target = root / name
            if url.path:
                candidate = target.parent / unquote(url.path)
                try:
                    # Lexical normalisation preserves symlink ancestors for the
                    # no-follow input check; resolving would erase that evidence.
                    relative = Path(os.path.abspath(candidate)).relative_to(root).as_posix()
                except ValueError:
                    report.add("documentation.local-link", name)
                    continue
                target = relative_path(root, relative)
            if not target.is_file():
                report.add("documentation.local-link", name)
            elif url.fragment and target.suffix == ".md":
                if name.startswith("docs/") and target.is_relative_to(root / "docs"):
                    built_links.append(
                        (name, target.relative_to(root / "docs").as_posix(), unquote(url.fragment))
                    )
                else:
                    linked = page(read_text(root, target.relative_to(root).as_posix()))
                    if unquote(url.fragment) not in linked.anchors:
                        report.add("documentation.local-link", name)
    for name, digest in ASSETS.items():
        if hashlib.sha256(read_bytes(root, name, MAX_FILE)).hexdigest() != digest:
            report.add("documentation.asset-drift", name)
    if yaml_object(root, ".github/FUNDING.yml") != FUNDING:
        report.add("documentation.funding-drift", ".github/FUNDING.yml")
    native_documentation(root, report)
    if report.exit_code != 0:
        return
    configuration = read_bytes(root, "mkdocs.yml")
    if hashlib.sha256(configuration).hexdigest() != MKDOCS_SHA256:
        report.add("documentation.renderer-failure", "mkdocs.yml")
        return
    if [name for name in files if name.startswith("overrides/")] != ["overrides/main.html"]:
        report.add("documentation.renderer-failure", "overrides/main.html")
        return
    template = read_bytes(root, "overrides/main.html")
    if hashlib.sha256(template).hexdigest() != DOCUMENTATION_TEMPLATE_SHA256:
        report.add("documentation.renderer-failure", "overrides/main.html")
        return
    hook = read_bytes(root, "tools/local_scaffold/documentation_fragments.py")
    if hashlib.sha256(hook).hexdigest() != DOCUMENTATION_FRAGMENT_HOOK_SHA256:
        report.add(
            "documentation.renderer-failure", "tools/local_scaffold/documentation_fragments.py"
        )
        return
    cache = root / ".tool-cache"
    if cache.is_symlink():
        raise Fault("repository_inventory.symlink-entry", ".tool-cache")
    cache.mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="docs-", dir=cache))
    try:
        with tempfile.TemporaryDirectory(prefix="renderer-", dir=cache) as staging:
            workspace = Path(staging)
            templates = workspace / "overrides"
            templates.mkdir()
            (templates / "main.html").write_bytes(template)
            captured_hook = workspace / "documentation_fragments.py"
            captured_hook.write_bytes(hook)
            projected = (
                configuration.decode()
                .replace(
                    "watch: [src, tools]",
                    "docs_dir: "
                    + json.dumps(str(root / "docs"))
                    + "\nwatch: ["
                    + json.dumps(str(root / "src"))
                    + ", "
                    + json.dumps(str(root / "tools"))
                    + "]",
                )
                .replace("  custom_dir: overrides", "  custom_dir: " + json.dumps(str(templates)))
                .replace(
                    "paths: [src, tools]",
                    "paths: ["
                    + json.dumps(str(root / "src"))
                    + ", "
                    + json.dumps(str(root / "tools"))
                    + "]",
                )
                .replace(
                    "hooks: [tools/local_scaffold/documentation_fragments.py]",
                    "hooks: [" + json.dumps(str(captured_hook)) + "]",
                )
            )
            config = workspace / "mkdocs.yml"
            config.write_text(projected)
            result = run_process(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    "mkdocs",
                    "build",
                    "--strict",
                    "--config-file",
                    str(config),
                    "--site-dir",
                    str(output),
                ],
                root,
            )
        if result.exit_code:
            report.add("documentation.renderer-failure", "mkdocs.yml")
        elif not (output / "index.html").is_file():
            report.add("documentation.renderer-failure", "docs/index.md")
        elif os.path.lexists(output / "internal"):
            report.add("documentation.private-plan", "docs/internal")
        if (output / "index.html").is_file() and not os.path.lexists(output / "internal"):
            rendered_fragments(output, built_links, report)
    finally:
        shutil.rmtree(output)
