# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance
"""Keep the hosted automation able to complete on the hosted runner and registry."""

import re
from typing import cast

from local_scaffold.inputs import Json, parse_yaml
from tests.conftest import SOURCE

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\;]+)", re.MULTILINE)


def test_hosted_tests_use_every_processor() -> None:
    """Run the hosted suite on one worker per hosted processor, within the job's bound.

    The serial suite does not finish inside the twenty minutes the workflow policy allows
    a job, so the hosted step selects four workers; the local default stays serial.
    """
    path = SOURCE / ".github/workflows/pre-commit.yml"
    workflow = parse_yaml(path.read_bytes(), ".github/workflows/pre-commit.yml", workflow=True)
    job = cast(dict[str, Json], cast(dict[str, Json], workflow["jobs"])["tests"])
    steps = cast(list[dict[str, Json]], job["steps"])
    suite = [step for step in steps if step.get("run") == "make test"]
    assert len(suite) == 1
    assert suite[0].get("env") == {"TEST_WORKERS": "4"}
    assert job["timeout-minutes"] == 20


def test_every_dependabot_lane_can_resolve_its_manifest() -> None:
    """Configure no Dependabot lane over a manifest the public registry cannot resolve.

    The development lock pins the maintained RFC wheel by a local version label that
    the public registry does not serve, so a pip lane would fail every update while
    that pin stands. The GitHub Actions lane keeps every pinned action current.
    """
    config = parse_yaml((SOURCE / ".github/dependabot.yml").read_bytes(), ".github/dependabot.yml")
    lanes = cast(list[dict[str, Json]], config["updates"])
    ecosystems = {lane["package-ecosystem"] for lane in lanes}
    requirements = (SOURCE / "requirements-dev.txt").read_text(encoding="utf-8")
    local = sorted(name for name, version in _PIN.findall(requirements) if "+" in version)
    assert local == ["rfc8785"]
    assert "github-actions" in ecosystems
    assert "pip" not in ecosystems
