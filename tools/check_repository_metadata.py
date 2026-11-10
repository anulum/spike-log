# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Public command for the complete repository metadata operation."""

from local_scaffold.cli import main as dispatch


def main(arguments: list[str] | None = None) -> int:
    """Run the fixed repository_metadata public operation.

    Parameters
    ----------
    arguments : list[str] | None
        Explicit CLI tokens, or process arguments when None. Invalid options
        are refused without reflecting received values.

    Returns
    -------
    int
        Native exit 0 for success, 2 for refusal or output failure, 3 for
        unavailability or interruption, or 4 for invalid invocation or
        configuration.
    """
    return dispatch("repository_metadata", arguments)


if __name__ == "__main__":
    raise SystemExit(main())
