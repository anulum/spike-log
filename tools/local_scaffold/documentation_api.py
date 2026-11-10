# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check documented payload imports against the fixed actual public implementation."""

import ast
import hashlib
import re
from pathlib import Path

from .bindings import PAYLOAD_API_NAMES, PAYLOAD_API_SOURCE_SHA256
from .inputs import read_bytes


def imports_supported(root: Path, text: str) -> bool:
    """Validate literal payload imports without importing received repository code.

    Parameters
    ----------
    root : Path
        Received source tree, inspected only as bounded no-follow file data.
    text : str
        Full maintained Markdown. Literal one-line package imports are checked
        against this installation's fixed public names and source identities.

    Returns
    -------
    bool
        True when no package import is present, or every complete import names
        actual supported symbols and all enrolled source bodies match the trusted
        installation's fixed identities. Unknown, mixed, wildcard and malformed
        imports cannot advertise a missing operation.
    """
    statements = re.findall(r"\bfrom[ \t]+spike_log[ \t]+import[^\n]*", text)
    if not statements:
        return True
    for statement in statements:
        try:
            tree = ast.parse(statement)
        except SyntaxError:
            return False
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.ImportFrom):
            return False
        if any(alias.name not in PAYLOAD_API_NAMES for alias in tree.body[0].names):
            return False
    return all(
        hashlib.sha256(read_bytes(root, name)).hexdigest() == digest
        for name, digest in PAYLOAD_API_SOURCE_SHA256.items()
    )
