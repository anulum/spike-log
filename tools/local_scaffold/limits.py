# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance


"""Reviewed limits constants for local repository validation."""

from typing import Final

MAX_INPUT: Final = 1_048_576


MAX_DEPTH: Final = 64


MAX_VALUES: Final = 100_000


MAX_STRING: Final = 65_536


MAX_ENTRIES: Final = 4_096


MAX_TREE_DEPTH: Final = 32


MAX_PATH: Final = 1_024


MAX_FILE: Final = 16_777_216


MAX_TREE: Final = 134_217_728


MAX_CAPTURE: Final = 262_144


MAX_REPORT: Final = 524_288


LEAF_SECONDS: Final = 120.0


PREFLIGHT_SECONDS: Final = 600.0


EXCLUDED: Final = frozenset(
    {
        ".git",
        ".venv",
        "node_modules",
        "target",
        ".tool-cache",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "__pycache__",
    }
)
