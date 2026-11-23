# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Run the fixed stdlib-only environment input acquisition under the selected base Python."""

import sys
from pathlib import Path


def main(arguments: list[str] | None = None) -> int:
    """Dispatch the fixed installed source independently of the selected roots.

    Parameters
    ----------
    arguments : list[str] | None
        Explicit selections or native process arguments.

    Returns
    -------
    int
        Native acquisition result 0/2/3/4.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from local_scaffold.input_fetch_cli import main as dispatch

    return dispatch(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
