# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — actual Markdown fragment normalization and native hook wiring

"""Exercise the registered extension through real Markdown and MkDocs renderers."""

import subprocess
from pathlib import Path
from xml.etree.ElementTree import fromstring

import markdown
import pytest
from mkdocs.exceptions import PluginError

from local_scaffold.documentation_fragments import FragmentExtension, on_page_content
from tests.conftest import SOURCE, payload, run_guard, snapshots, source_python


@pytest.mark.parametrize(
    "source,tag,attribute,expected",
    [
        ("[API](guide.md#rate%2Estep%5F1)", "a", "href", "guide.md#rate.step_1"),
        (
            "[API](guide%2Emd?mode=%2F#rate%2Estep)",
            "a",
            "href",
            "guide%2Emd?mode=%2F#rate.step",
        ),
        (
            "[API](https://example.invalid/guide#rate%2Estep)",
            "a",
            "href",
            "https://example.invalid/guide#rate%2Estep",
        ),
        (
            "[API](//example.invalid/guide#rate%2Estep)",
            "a",
            "href",
            "//example.invalid/guide#rate%2Estep",
        ),
        ("[API](guide.md#rate%2Fstep%25x%23y)", "a", "href", "guide.md#rate%2Fstep%25x%23y"),
        ("[API](guide.md)", "a", "href", "guide.md"),
        ("[API](guide.md#bad%2Xescape)", "a", "href", "guide.md#bad%2Xescape"),
        ("![diagram](diagram.png#p%2Eq)", "img", "src", "diagram.png#p%2Eq"),
    ],
)
def test_public_markdown_fragment_components(
    source: str, tag: str, attribute: str, expected: str
) -> None:
    """Preserve URI components while normalizing only local unreserved fragments."""
    rendered = markdown.Markdown(extensions=[FragmentExtension()]).convert(source)
    element = fromstring(rendered).find(tag)
    assert element is not None
    assert element.attrib[attribute] == expected


def test_all_rfc_unreserved_fragment_characters() -> None:
    """Render all 66 normative characters in uppercase and lowercase escape forms."""
    expected = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
    assert len(expected) == 66
    for spelling in ("02X", "02x"):
        fragment = "".join("%" + format(ord(character), spelling) for character in expected)
        rendered = markdown.Markdown(extensions=[FragmentExtension()]).convert(
            "[API](#" + fragment + ")"
        )
        link = fromstring(rendered).find("a")
        assert link is not None
        assert link.attrib["href"] == "#" + expected


def test_actual_configured_native_fragment_hook(tmp_path: Path) -> None:
    """Execute the canonical configuration and hook through the real native CLI."""
    result = subprocess.run(
        source_python(
            "-I",
            "-m",
            "mkdocs",
            "build",
            "--strict",
            "--config-file",
            str(SOURCE / "mkdocs.yml"),
            "--site-dir",
            str(tmp_path / "native-site"),
        ),
        cwd=SOURCE,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (tmp_path / "native-site/validation-tooling/index.html").is_file()


@pytest.mark.parametrize(
    "source,accepted",
    [
        ('<span id="decoded.anchor"></span>', True),
        ('<span name="opaque%2Evalue"></span>', True),
        ("<span hidden>Ordinary hidden content</span>", True),
        ('<span id="encoded%2Eanchor"></span>', False),
        ('<a name="encoded%2Eanchor"></a>', False),
    ],
)
def test_actual_rendered_anchor_definition_profile(source: str, accepted: bool) -> None:
    """Validate actual Markdown output without treating arbitrary names as anchors."""
    html = markdown.Markdown(extensions=[FragmentExtension()]).convert(source)
    if accepted:
        assert on_page_content(html) == html
    else:
        with pytest.raises(PluginError, match="Anchor identifiers must use decoded characters"):
            on_page_content(html)


def test_public_guard_refuses_encoded_site_identifier(root: Path) -> None:
    """Refuse an unsupported anchor definition through the complete native pipeline."""
    path = root / "docs/index.md"
    path.write_text(path.read_text() + '\n<span id="encoded%2Eanchor"></span>\n')
    before = snapshots(root)
    report = payload(run_guard("documentation", root), 2)
    reasons = report["reasons"]
    assert isinstance(reasons, list)
    assert any(
        isinstance(reason, dict) and reason["code"] == "documentation.renderer-failure"
        for reason in reasons
    )
    assert snapshots(root) == before
