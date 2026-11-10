# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Create genuine wheel-bound test producers with the shared uv package cache."""

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from tests.conftest import SOURCE


def producer_environment(directory: Path, wheels: Sequence[Path]) -> Path:
    """Create an isolated interpreter and install the selected real wheel producers.

    Parameters
    ----------
    directory : Path
        Owned new environment directory on the shared cache filesystem.
    wheels : Sequence[Path]
        Wheel files whose original identities are checked by the owning fixture.

    Returns
    -------
    Path
        Interpreter using only the selected installed producers.
    """
    uv = SOURCE / ".venv/bin/uv"
    cache = subprocess.run(
        [str(uv), "cache", "dir"], capture_output=True, text=True, timeout=10, check=True
    ).stdout.strip()
    directory.parent.mkdir(parents=True, exist_ok=True)
    assert Path(cache).stat().st_dev == directory.parent.stat().st_dev
    subprocess.run(
        [
            str(uv),
            "--no-config",
            "venv",
            "--python",
            sys.executable,
            "--no-python-downloads",
            "--link-mode",
            "hardlink",
            str(directory),
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    python = directory / "bin/python"
    subprocess.run(
        [
            str(uv),
            "--no-config",
            "pip",
            "install",
            "--python",
            str(python),
            "--no-index",
            "--no-deps",
            "--cache-dir",
            cache,
            "--link-mode",
            "hardlink",
            *map(str, wheels),
        ],
        capture_output=True,
        timeout=30,
        check=True,
    )
    return python
