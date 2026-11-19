<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Commercial license available
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
SPIKE-LOG — source and configuration provenance
-->

# Contributing

Bootstrap runs on CPython 3.13.18 on Linux x86-64. Select BASE_PYTHON,
ENVIRONMENT_INPUTS and ENVIRONMENT_OWNER_SOURCE explicitly before creating or
updating an environment. ENVIRONMENT_INPUTS is a flat directory containing
every original artifact selected by the frozen development provenance,
the two local package responses and their original manifest/build inputs.
ENVIRONMENT_OWNER_SOURCE is the separately supplied Common source tree.
Use the exact producer commit named in the frozen owner source manifest.
The CI workflow policy uses the same CPython patch version. A runner also
needs the independently supplied frozen inputs and Common source before it can
run the bootstrap.

Check readiness before installation:

```sh
make check-environment-inputs \
  BASE_PYTHON="$BASE_PYTHON" \
  ENVIRONMENT_INPUTS="$ENVIRONMENT_INPUTS" \
  ENVIRONMENT_OWNER_SOURCE="$ENVIRONMENT_OWNER_SOURCE"
```

Then invoke `make environment` with the same selections. The default destination
is .venv; ENVIRONMENT_DIR selects an owned alternative. Both commands require
the exact frozen development input, development lock, runtime lock and
dependency provenance. Missing, changed or unsafe operands refuse; neither
command regenerates the locks or downloads a replacement.

The readiness check reads source and artifact bytes only. It verifies the
selected interpreter and destination, all selected artifact identities,
both local source responses, their owner manifest and build inputs, and the
manifest's actual source files. The complete read budget is at most 128 MiB;
ENVIRONMENT_INPUT_BYTES can reduce it. Repeated references to the identical
owner manifest share one source-tree verification within that operation.
No environment, cache, bootstrap binary, builder lock or bytecode is created
before readiness passes. The public `tools/check_environment_inputs.py` accepts
the same explicit roots, an environment destination and an optional reduced
`--max-input-bytes` budget; `--json` selects the standard seven-field report.

After readiness, the target extracts the exact uv executable from its selected
wheel and verifies its digest. It installs the locked pip and Poetry builders,
then the complete hash-required development graph with `--no-index` and
`--find-links` pointing only at the selected artifact directory. It runs native
`uv pip check` afterward. There is no registry fallback for local packages.
Hardlink installation uses the configured shared uv cache; the cache and
environment must share a filesystem. UV_CACHE_DIR selects the shared cache.

Existing environments are not recreated. The selected destination must be
absent, empty, or an environment using that same interpreter without system
site packages. It must not overlap either read-only input tree. Ensure no
process is using an environment before changing its installed graph.

Input readiness does not establish an installed producer, complete source or
security acceptance, scientific qualification, or permission to publish.
The metadata and dependency commands independently enforce their enrolled
installation profile; a successful readiness report does not waive a mismatch.

The lock includes the verified source builder required for REUSE. Native Actionlint and Gitleaks artifacts are named with their immutable publisher URLs and SHA-256 in `dependency-provenance.json`; place verified extractions at their recorded `.tool-cache` paths. CodeQL workflow preparation is for the separately authorised hosting lifecycle. Genuine local Python source security analysis uses Bandit. Do not interpret preparation as a hosted CodeQL result.

Run `make quality`, `make docs`, the guard commands in [VALIDATION.md](VALIDATION.md), and meaningful targeted tests for the changed public boundaries. The complete `make test` target belongs to authorised CI or the explicit pre-publication verification stage. Locally run targeted tests serially with low priority and project-local temporary storage. Every maintained Python module, test and helper requires native documentation and strict typing. New guard code requires meaningful 100% statement and branch coverage through public command/file/process behaviour. Missing tools remain failures; do not use skips, mocks or lowered thresholds to clear acceptance.

Keep source changes narrowly owned. Review licences, locked dependencies, safe workflow permissions, real failure handling and the staged diff before committing. Initial local history uses main with zero remotes. Private working records, credentials, generated caches and large evidence artefacts stay outside published source. A source change does not itself authorise push, release or deployment.

## Reproduce the locked dependency graph

From the repository root, use the existing locked environment to write a
separate candidate without changing dependency versions:

```sh
.venv/bin/uv --no-config pip compile \
  --python .venv/bin/python \
  --constraints requirements-dev.txt \
  --generate-hashes --no-header \
  --no-emit-index-url --no-emit-find-links --no-build-isolation \
  --default-index https://pypi.org/simple --keyring-provider disabled \
  --cache-dir "$(.venv/bin/uv cache dir)" \
  --output-file .tool-cache/requirements-reproduced.txt \
  requirements-dev.in
```

This is a replay of the frozen graph. The complete original lock constrains
resolution; the command does not request an upgrade. Compare every package
version and its complete set of hashes. Copyright and invocation comments
are outside that package comparison. The generated candidate stays in the
local tool cache; adopting a changed lock also requires the matching source
provenance and tooling bindings.

`dependency-provenance.json` records installed METADATA identities, declared
licence-file hashes, selected source-artifact descriptors and original
registry-response hashes. `metadata_sha256` hashes the UTF-8 encoding of
the text returned by native `Distribution.read_text("METADATA")`. The supported
filesystem distribution uses text-mode newline normalisation. Registry-response
and declared licence-file digests bind their original raw bytes. `official_metadata_sha256` binds the complete
original version-metadata response bytes. It does not hash only the `info`
object or a reserialised JSON document. Preserve those original response bytes
as regeneration inputs: a later response for the same version can differ.
Installed dependency and licence fields retain their recorded source and
ordering rather than being replaced with current registry values.


## Preserve source inputs when regenerating provenance

Use `make prepare-provenance-inputs` to prepare all raw version responses,
then `make provenance-generate` to write a separate prospective manifest.
Compare that candidate with
`make provenance-verify PROVENANCE_REFERENCE=.tool-cache/dependency-provenance.prospective.json`.
Choose another `PROVENANCE_OUTPUT` for a later candidate and use that exact
path as its comparison reference. Existing output is never replaced.

Capture runs under the installed supervisor's default inclusive budget of 120 seconds. Use `PROVENANCE_CAPTURE_SECONDS` on `make prepare-provenance-inputs`
for a smaller positive finite budget; `--capture-seconds` is the corresponding
capture-only CLI option. Timeout remains unavailable and retains partial files.

Complete existing source snapshots are revalidated offline and retained.
An incomplete directory stays incomplete; select a new input directory for
a new capture. Baseline, direct-input and lock byte identities are reviewed
together. Later same-version metadata is not a replacement for missing
historical raw bytes. The [source workflow](docs/validation-tooling.md#offline-source-workflow)
distinguishes capture, offline generation/comparison and audit admission.

`make prepare-test-inputs` includes source preparation and also runs other
explicit fixture/audit preparation. Owning tests can use the registry and
vulnerability service; the complete test/preflight path is not network-free.

`make prepare-provenance-identity-fixture` prepares one original older wheel as
metadata test data, using its fixed publisher URL, byte limit and SHA-256.
The focused record-identity tests use native distribution discovery to compare
that metadata with the selected record. They do not install the wheel or import
its package code. The development dependency graph retains its locked versions.
