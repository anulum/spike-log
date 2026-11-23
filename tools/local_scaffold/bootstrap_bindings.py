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
    "requirements-dev.txt": "780ad088aedf6aec5edf31193e4438ecb4c47932d5ecbaff7e12a01e44d01c5d",
    "requirements-runtime.txt": "75544d0ed11bb08b393c0c22b950e13753fe1ba57404ed4721beb5fb4ae19e44",
    "dependency-provenance.json": "331bb5f8d8acb339ef5a3ea1c50ed8c1af1aa2dc2a96f96643072b4d33b7470b",
}
