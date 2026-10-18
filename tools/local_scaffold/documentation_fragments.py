# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — canonical local documentation fragment spellings

"""Normalize equivalent unreserved fragment escapes before native validation."""

from __future__ import annotations

import re
import string
from html.parser import HTMLParser
from typing import Final
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element

from markdown import Markdown
from markdown.extensions import Extension
from markdown.treeprocessors import Treeprocessor
from mkdocs.config.defaults import MkDocsConfig
from mkdocs.exceptions import PluginError

UNRESERVED: Final = frozenset(string.ascii_letters + string.digits + "-._~")
ESCAPE: Final = re.compile(r"%([0-9a-fA-F]{2})")


def decode_unreserved(match: re.Match[str]) -> str:
    """Decode one RFC 3986 unreserved escape, retaining every other spelling.

    Parameters
    ----------
    match : re.Match[str]
        One complete percent escape with its two hexadecimal digits captured.

    Returns
    -------
    str
        Equivalent unreserved ASCII character or the unchanged reserved escape.
    """
    character = chr(int(match.group(1), 16))
    return character if character in UNRESERVED else match.group(0)


class FragmentTreeprocessor(Treeprocessor):
    """Canonicalize local Markdown anchor fragments before MkDocs records them."""

    def run(self, root: Element) -> None:
        """Normalize unreserved fragment escapes in place.

        Parameters
        ----------
        root : Element
            Actual Markdown element tree; paths, queries, images and external URLs retain their spelling.
        """
        for element in root.iter("a"):
            href = element.get("href", "")
            parsed = urlsplit(href)
            if parsed.scheme or parsed.netloc or "#" not in href:
                continue
            prefix, _, fragment = href.partition("#")
            element.set("href", prefix + "#" + ESCAPE.sub(decode_unreserved, fragment))


class FragmentExtension(Extension):
    """Register fragment normalization before the native relative-link processor."""

    def extendMarkdown(self, md: Markdown) -> None:
        """Install the processor without changing native validation settings.

        Parameters
        ----------
        md : Markdown
            Actual renderer instance receiving a processor before native priority-zero link validation.
        """
        md.treeprocessors.register(FragmentTreeprocessor(md), "spike_log_fragments", priority=1)


def on_config(config: MkDocsConfig) -> MkDocsConfig:
    """Register the loaded hook as a native Python-Markdown extension.

    Parameters
    ----------
    config : MkDocsConfig
        Validated native configuration, including its unchanged strict link checks.

    Returns
    -------
    MkDocsConfig
        Same configuration with the loaded hook's extension name appended.
    """
    config.markdown_extensions.append(__name__ + ":FragmentExtension")
    return config


class AnchorDefinitions(HTMLParser):
    """Require decoded site identifiers before admitting fragment normalization."""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Refuse percent escapes in actual id or legacy named-anchor definitions.

        Parameters
        ----------
        tag : str
            Actual generated HTML element; legacy named anchors require an a element.
        attrs : list[tuple[str, str | None]]
            Actual generated attributes inspected without changing their values.

        Raises
        ------
        PluginError
            Raised with fixed text for an encoded anchor identifier.
        """
        for key, value in attrs:
            if value and (key == "id" or (tag == "a" and key == "name")):
                if ESCAPE.search(value):
                    raise PluginError("Anchor identifiers must use decoded characters.")


def on_page_content(html: str, **context: object) -> str:
    """Check actual final anchor definitions and preserve the generated HTML.

    Parameters
    ----------
    html : str
        Actual page output after Markdown and documentation-plugin rendering.
    **context : object
        Native page, configuration and file context, unused by this rule.

    Returns
    -------
    str
        Unchanged HTML after all anchor identifiers meet the declared profile.

    Raises
    ------
    PluginError
        Raised if an actual id or legacy a-name contains a percent escape.
    """
    AnchorDefinitions().feed(html)
    return html
