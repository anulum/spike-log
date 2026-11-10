# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — public environment input check

"""Run the fixed stdlib-only pre-mutation check under the selected base Python."""

import sys
from pathlib import Path


def main(arguments: list[str] | None = None) -> int:
    """Dispatch the fixed installed source independently of inspected data roots.

    Parameters
    ----------
    arguments : list[str] | None
        Explicit data selections or native process arguments.

    Returns
    -------
    int
        Native input-readiness0/2/3/4, without creating runtime state.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from local_scaffold.bootstrap_cli import main as dispatch

    return dispatch(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
