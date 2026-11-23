<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->
# Vendored environment inputs

The development and runtime locks select two packages that no registry
serves: the first-party `evidence-manifest-toolkit` wheel, built from the
Common source, and the maintained `rfc8785` 0.1.4+emt.1 wheel. This
directory holds both wheels and the seven records that bind them to their
owner source. `dependency-provenance.json` and the locks pin every one of
these files; the readiness check verifies them against the owner source
checkout before anything is installed.

The owner source is the public
[evidence-manifest-toolkit](https://github.com/anulum/evidence-manifest-toolkit)
repository at commit `2db2055b6f01d0aac352baae25ccdcce513e54dc`.

| File | Content |
| --- | --- |
| `evidence_manifest_toolkit-0.0.0.dev0-py3-none-any.whl` | First-party wheel built from the owner source |
| `rfc8785-0.1.4+emt.1-py3-none-any.whl` | Maintained wheel, Apache-2.0, from the owner source's vendored build |
| `owner-source-inputs.json` | Every file of the owner commit: path, byte count and SHA-256 |
| `common-wheel-source-identity.json` | The wheel's product files, each equal to its owner source file |
| `common-sdist-rebuild-identity.json` | The sdist, and the wheel rebuilt from it byte for byte |
| `common-build-producer.json` | The build: procedure, inputs, checks and artifact identities |
| `evidence-manifest-toolkit.json` | The first-party wheel's references to its manifest and build records |
| `rfc8785.json` | The maintained wheel's references to its manifest and source provenance |
| `rfc8785-source-provenance.json` | The maintained wheel's upstream release, patch and builder |

The first-party wheel and its sdist were built from `git archive` of the
owner commit with the owner source's pinned backend, `poetry-core` 2.5.0,
under CPython 3.13.18 and `SOURCE_DATE_EPOCH=1793779662`. The same
procedure rebuilds the wheel from the sdist byte for byte.

The owner commit, the vendored manifest and the records derived from it
change only together, in one reviewed change.
