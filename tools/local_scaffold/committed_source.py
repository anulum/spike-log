# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Bind independently selected owner source bytes to the actual clean committed tree."""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path

from .inputs import Json
from .limits import LEAF_SECONDS
from .processes import run_process
from .reports import Fault


def verify_committed_source(
    owner: Path, manifest: Mapping[str, Json], files: Mapping[str, bytes]
) -> None:
    """Verify the complete pinned source against its actual native Git commit.

    Parameters
    ----------
    owner : Path
        Explicit operator-selected source root, never selected by received metadata.
    manifest : Mapping
        Complete manifest already bound to the independent baseline digest.
    files : Mapping
        Complete original source bytes already verified against every manifest row.

    Raises
    ------
    Fault
        Invalid commit identities, changed files, an incomplete tree or a dirty
        native owner checkout refuse. Native Git has a shared finite deadline.

    Notes
    -----
    Git receives only fixed data-reading operations. Hooks, fsmonitor, replacement
    objects, external configuration and paging cannot select executable callbacks.
    This establishes source correspondence, not security or scientific admission.
    """
    if (
        set(manifest) != {"schema", "repository", "commit", "tree", "files"}
        or manifest["schema"] != "spike_log.committed-owner-source.v1"
        or manifest["repository"] != "EVIDENCE-MANIFEST-TOOLKIT"
    ):
        raise Fault("configuration_invalid", "committed-source", 4)
    commit, tree = manifest["commit"], manifest["tree"]
    if any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None
        for value in (commit, tree)
    ):
        raise Fault("configuration_invalid", "committed-source", 4)
    deadline = time.monotonic() + LEAF_SECONDS
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.devnull,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    prefix = [
        "/usr/bin/git",
        "--no-pager",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        str(owner),
    ]
    operations = (
        ["rev-parse", "--verify", "HEAD"],
        ["rev-parse", "--verify", "HEAD^{tree}"],
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        ["ls-tree", "-rz", "--full-tree", "HEAD"],
    )
    outputs = []
    for arguments in operations:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Fault("tool_timeout", "committed-source", 3)
        result = run_process(prefix + arguments, owner, remaining, environment=environment)
        if result.exit_code:
            raise Fault("source_identity_mismatch", "committed-source")
        outputs.append(result.stdout)
    if (
        outputs[0] != (str(commit) + "\n").encode()
        or outputs[1] != (str(tree) + "\n").encode()
        or outputs[2]
    ):
        raise Fault("source_identity_mismatch", "committed-source")
    expected = {
        name.encode(): hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data, usedforsecurity=False
        )
        .hexdigest()
        .encode()
        for name, data in files.items()
    }
    actual = {}
    for entry in outputs[3].split(b"\0"):
        if not entry:
            continue
        metadata, separator, name = entry.partition(b"\t")
        fields = metadata.split()
        if (
            not separator
            or len(fields) != 3
            or fields[0] not in (b"100644", b"100755")
            or fields[1] != b"blob"
            or name in actual
        ):
            raise Fault("source_identity_mismatch", "committed-source")
        actual[name] = fields[2]
    if actual != expected:
        raise Fault("source_identity_mismatch", "committed-source")
    if time.monotonic() >= deadline:
        raise Fault("tool_timeout", "committed-source", 3)
