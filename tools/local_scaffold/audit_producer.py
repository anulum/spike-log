# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Produce a genuine current audit and durably admit only that native operation."""

from __future__ import annotations

import os
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .audit_context import (
    ADVISORY_SOURCE,
    REGISTRY_GRAPH,
    VULNERABILITY_ENDPOINT,
    VULNERABILITY_SERVICE,
    context,
    encode,
    trusted_root,
)
from .audit_records import HEAD_SCHEMA, RECEIPT_SCHEMA, audit
from .audit_store import LOCATION, open_store
from .dependencies import verify_sources_and_producers
from .inputs import Json
from .policy import EXPECTED_GRAPH, LEAF_SECONDS
from .processes import ProcessObservation, run_process
from .reports import DiagnosticLimit, Fault, Report
from .security import historical_source


def produce(root: Path, report: Report) -> None:
    """Admit a real fixed producer attempt; received repositories cannot select trust.

    Native advisory IDs, aliases and fix versions remain in the bounded JSON
    result. Long prose descriptions are not requested from the producer.
    Receipts bind OSV and its endpoint to the actual query interval. OSV does
    not expose a global database revision; that value remains unavailable.

    Parameters
    ----------
    root : Path
        Validated inspected root, required to equal this actual trusted installation.
    report : Report
        Receives genuine source/environment/native/findings/publication outcomes.

    Raises
    ------
    Fault
        Raised for foreign roots, native resource failure or incomplete publication.
    KeyboardInterrupt
        Propagates only after retaining an unavailable terminal attempt when publication remains possible.
    """
    if root != trusted_root():
        raise Fault("policy_refusal")
    deadline = time.monotonic() + LEAF_SECONDS
    verify_sources_and_producers(root, report)
    historical_source(root, report)
    if report.exit_code:
        return
    bound = context()
    generation = uuid.uuid4().hex
    head: dict[str, Json] = {
        "schema": HEAD_SCHEMA,
        "generation": generation,
        "state": "pending",
        "receipt_sha256": None,
    }
    with open_store(root, write=True) as store:
        store.publish_head(encode(head))
        started = datetime.now(UTC)
        observation = ProcessObservation()
        count = 0
        outcome = "unavailable"
        interrupted = False
        try:
            cache = root / LOCATION / ("http-" + generation)
            os.mkdir("http-" + generation, mode=0o700, dir_fd=store.directory)
            environment = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(cache),
                "TMPDIR": str(cache),
                "TMP": str(cache),
                "TEMP": str(cache),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PIP_CONFIG_FILE": os.devnull,
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_NO_INPUT": "1",
            }
            requirements = cache / "registry-requirements.txt"
            with requirements.open("x") as stream:
                stream.write(
                    "".join(
                        name + "==" + version + "\n"
                        for name, version in sorted(REGISTRY_GRAPH.items())
                    )
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Fault("tool_timeout", LOCATION, 3)
            result = run_process(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-m",
                    "pip_audit",
                    "--strict",
                    "--no-deps",
                    "--disable-pip",
                    "-r",
                    str(requirements),
                    "--vulnerability-service",
                    VULNERABILITY_SERVICE,
                    "--osv-url",
                    VULNERABILITY_ENDPOINT,
                    "--format",
                    "json",
                    "--desc",
                    "off",
                    "--progress-spinner",
                    "off",
                    "--cache-dir",
                    str(cache),
                ],
                cache,
                remaining,
                observation=observation,
                environment=environment,
            )
            count = audit(result.stdout, report)
            if result.exit_code:
                report.add("tool_failed", LOCATION)
            if context() != bound:
                report.add("source_identity_mismatch", LOCATION)
            outcome = "clean" if report.exit_code == 0 else "refused"
        except (Fault, DiagnosticLimit) as error:
            if isinstance(error, Fault):
                try:
                    report.observe(error)
                except DiagnosticLimit:
                    pass
                outcome = {2: "refused", 3: "unavailable", 4: "invalid"}[error.exit_code]
            else:
                outcome = "refused"
        except KeyboardInterrupt:
            interrupted = True
            report.add("interrupted", LOCATION, 3)
        except OSError as error:
            raise Fault("output_failure", LOCATION) from error
        stdout = bytes(observation.stdout)
        stderr = bytes(observation.stderr)
        record: dict[str, Json] = {
            "schema": RECEIPT_SCHEMA,
            "generation": generation,
            "producer": "pip-audit",
            "producer_version": EXPECTED_GRAPH["pip-audit"],
            "advisory_source": ADVISORY_SOURCE,
            "outcome": outcome,
            "native_exit": observation.native_exit,
            "started_at": started.isoformat(),
            "produced_at": None
            if observation.native_completed_at is None
            else observation.native_completed_at.isoformat(),
            **bound,
            "audit_sha256": store.object(stdout) if stdout else None,
            "stdout_sha256": store.object(stdout),
            "stderr_sha256": store.object(stderr),
            "component_count": count,
        }
        if outcome == "clean":
            if time.monotonic() >= deadline:
                record["outcome"] = "unavailable"
                report.add("tool_timeout", LOCATION, 3)
            else:
                store.publish_audit(stdout)
        head.update({"state": "terminal", "receipt_sha256": store.object(encode(record))})
        store.publish_head(encode(head))
        if interrupted:
            raise KeyboardInterrupt
