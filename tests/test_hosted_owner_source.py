# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance
"""Bind every hosted environment job's owner source to the vendored owner manifest."""

import json
from typing import cast

from local_scaffold.inputs import Json, parse_yaml
from tests.conftest import SOURCE

OWNER = ".tool-cache/owner-source"
MANIFEST = SOURCE / "vendor/environment-inputs/owner-source-inputs.json"


def _environment_jobs() -> dict[str, dict[str, Json]]:
    """Return every hosted job that installs the environment, parsed as the workflow policy parses it.

    Returns
    -------
    dict
        Each job that runs ``make environment``, by ``<workflow file>/<job id>``.
    """
    jobs: dict[str, dict[str, Json]] = {}
    for path in sorted((SOURCE / ".github/workflows").glob("*.yml")):
        name = ".github/workflows/" + path.name
        workflow = parse_yaml(path.read_bytes(), name, workflow=True)
        for job_id, job in cast(dict[str, dict[str, Json]], workflow["jobs"]).items():
            steps = cast(list[dict[str, Json]], job.get("steps", []))
            if any(step.get("run") == "make environment" for step in steps):
                jobs[path.name + "/" + job_id] = job
    return jobs


def _index(steps: list[dict[str, Json]], run: str) -> int:
    """Return the position of the one step that runs exactly this command.

    Parameters
    ----------
    steps : list of dict
        The job's steps.
    run : str
        The command the step runs.

    Returns
    -------
    int
        Its position; exactly one step runs it.
    """
    positions = [n for n, step in enumerate(steps) if step.get("run") == run]
    assert len(positions) == 1, run
    return positions[0]


def test_every_environment_job_checks_out_and_selects_the_manifest_owner_commit() -> None:
    """Each job that installs the environment checks out the manifest's commit first and selects it.

    make environment runs the readiness check, which reads the owner tree, so every such
    job needs it. The commit is the one the vendored owner manifest records, so re-pinning
    the Common inputs without moving the hosted checkouts fails here, not on the runner.
    """
    manifest = cast(dict[str, Json], json.loads(MANIFEST.read_bytes()))
    assert cast(str, manifest["repository"]).casefold() == "evidence-manifest-toolkit"
    jobs = _environment_jobs()
    assert len(jobs) == 10
    for key, job in jobs.items():
        steps = cast(list[dict[str, Json]], job["steps"])
        owner = [
            n
            for n, step in enumerate(steps)
            if cast(dict[str, Json], step.get("with", {})).get("path") == OWNER
        ]
        assert owner == [1], key
        assert steps[1]["uses"] == steps[0]["uses"], key
        assert cast(str, steps[0]["uses"]).startswith("actions/checkout@"), key
        assert steps[1]["with"] == {
            "repository": "anulum/evidence-manifest-toolkit",
            "ref": manifest["commit"],
            "path": OWNER,
            "persist-credentials": False,
        }, key
        assert (
            1 < _index(steps, "make fetch-environment-inputs") < _index(steps, "make environment")
        )
        assert job["env"] == {"ENVIRONMENT_OWNER_SOURCE": OWNER}, key


def test_hosted_tests_give_the_capture_both_roots_and_the_vendored_snapshot() -> None:
    """The infrastructure tests revalidate the vendored snapshot with the inputs and the owner tree."""
    steps = cast(list[dict[str, Json]], _environment_jobs()["pre-commit.yml/tests"]["steps"])
    prepare = steps[_index(steps, "make prepare-test-inputs")]
    assert prepare["env"] == {
        "PROVENANCE_INPUTS": "vendor/provenance-inputs",
        "PROVENANCE_ARTIFACTS": ".tool-cache/environment-inputs",
        "PROVENANCE_OWNER_SOURCE": OWNER,
    }
    assert _index(steps, "make environment") < _index(steps, "make prepare-test-inputs")
    assert _index(steps, "make prepare-test-inputs") < _index(steps, "make test")
