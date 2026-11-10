# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Public entry point for source capture and offline provenance reconstruction."""

from local_scaffold.provenance_cli import main as dispatch


def main(arguments: list[str] | None = None) -> int:
    """Run source capture, prospective generation or read-only provenance comparison.

    Parameters
    ----------
    arguments : list[str] | None
        Explicit command tokens, or process arguments when None.

    Returns
    -------
    int
        Native status of the requested capture/generation/comparison operation; no audit admission is granted.
    """
    return dispatch(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
