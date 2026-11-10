# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — frozen environment input identities

"""Bind the complete proposed environment before any bootstrap mutation."""

from typing import Final

PYTHON_VERSION: Final = "3.13.18"
MAX_ARTIFACT_BYTES: Final = 20_000_000

SOURCE_PINS: Final = {
    "requirements-dev.in": "475e8f7028ac119b3ca8faeb2edf3e341e1e0f35fa2121101b56423f25d6ed0e",
    "requirements-dev.txt": "e44a99a8ab1d81d4be625b6b5c2583945bd04c26f020e357a0a5c868e67e41f3",
    "requirements-runtime.txt": "8151bf6671af70c0ff25dfc1ced0772b7fa4ea217ea115ef8e2bb746256fd7b6",
    "dependency-provenance.json": "83a2f263c9cd8d676618b9edf8dcd8da06012695d5917bed01d1a3c189541da5",
}
