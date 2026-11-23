# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Check deterministic dependency inventories through the real public Make target."""

import json
import os
import subprocess
from pathlib import Path

from tests.conftest import SOURCE
from tests.test_sbom_publication import native_sbom_root as native_sbom_root


def test_make_sbom_repeats_exact_bytes(native_sbom_root: Path) -> None:
    """Identical installed inputs yield identical complete SBOM bytes without an epoch."""
    environment = os.environ.copy()
    environment.pop("SOURCE_DATE_EPOCH", None)
    outputs: list[bytes] = []
    for attempt in range(2):
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "sbom",
                "PYTHON=" + str(SOURCE / ".venv/bin/python"),
            ],
            cwd=native_sbom_root,
            env=environment,
            capture_output=True,
            timeout=120,
        )
        assert result.returncode == 0, (result.stdout, result.stderr)
        produced = (native_sbom_root / ".tool-cache/sbom.json").read_bytes()
        (native_sbom_root / f".tool-cache/reproduction-{attempt}.json").write_bytes(produced)
        outputs.append(produced)
    assert outputs[0] == outputs[1]
    value = json.loads(outputs[0])
    assert value["bomFormat"] == "CycloneDX"
    packages = json.loads((SOURCE / "dependency-provenance.json").read_bytes())["packages"]
    assert len(value["components"]) == len(packages)
