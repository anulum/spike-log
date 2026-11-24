# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance


"""Reviewed bindings constants for local repository validation."""

from typing import Final

PYTHON_SUPPORTED_RANGE: Final = ">=3.13.18,<3.14"

ASSETS: Final = {
    "docs/assets/fortis_studio_logo.jpg": "844c5d764c8ad0a030e8f7b83c7e878bb4ebec42ea6e40223f65f344769568c0",
    "docs/assets/anulum_logo.png": "fe4b3b24226e87045d4aac09284f30ee8a83bd95f9af0509272a063e284067d3",
    "docs/assets/anulum_logo_company.jpg": "d98a731a2b4b3b8880979d2e2f2c5cb722cc45d3f75b988e81c301902c7d1143",
}


ACTIONS: Final = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
    "github/codeql-action": "1bd86f2fdb4b86187fa4059f16f31a3202acc9ea",
    "github/codeql-action/init": "1bd86f2fdb4b86187fa4059f16f31a3202acc9ea",
    "github/codeql-action/analyze": "1bd86f2fdb4b86187fa4059f16f31a3202acc9ea",
}


SCHEMA_SHA256: Final = "2f1faa22f6feeec2e3c6d30ca4dd71cf40feee6884861d41c6d73409f7559aa9"


LICENCE_SHA256: Final = "d8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee"


PROVENANCE_SHA256: Final = "331bb5f8d8acb339ef5a3ea1c50ed8c1af1aa2dc2a96f96643072b4d33b7470b"


LOCK_SHA256: Final = "780ad088aedf6aec5edf31193e4438ecb4c47932d5ecbaff7e12a01e44d01c5d"


EXPECTED_GRAPH: Final = {
    "arrow": "1.4.0",
    "attrs": "26.1.0",
    "babel": "2.18.0",
    "backrefs": "8.0",
    "bandit": "1.9.4",
    "boolean-py": "5.0",
    "cachecontrol": "0.14.4",
    "certifi": "2026.10.23",
    "cfgv": "3.5.0",
    "chardet": "7.6.0",
    "charset-normalizer": "3.5.2",
    "click": "8.5.0",
    "colorama": "0.4.6",
    "coverage": "7.16.2",
    "cyclonedx-bom": "7.5.0",
    "cyclonedx-python-lib": "11.12.0",
    "defusedxml": "0.7.1",
    "distlib": "0.4.3",
    "evidence-manifest-toolkit": "0.0.0.dev0",
    "execnet": "2.1.2",
    "filelock": "4.2.9",
    "fqdn": "1.6.0",
    "ghp-import": "2.1.0",
    "griffelib": "2.3.0",
    "identify": "2.6.20",
    "idna": "3.20",
    "iniconfig": "2.3.0",
    "isoduration": "20.11.0",
    "jinja2": "3.1.6",
    "jsonpointer": "3.1.1",
    "jsonschema": "4.26.0",
    "jsonschema-specifications": "2025.9.1",
    "lark": "1.3.1",
    "librt": "0.16.0",
    "license-expression": "30.4.4",
    "lxml": "6.1.3",
    "markdown": "3.11",
    "markdown-it-py": "4.2.0",
    "markupsafe": "3.0.3",
    "mdurl": "0.1.2",
    "mergedeep": "1.3.4",
    "mkdocs": "1.6.1",
    "mkdocs-autorefs": "1.4.4",
    "mkdocs-get-deps": "0.2.2",
    "mkdocs-material": "9.7.7",
    "mkdocs-material-extensions": "1.3.1",
    "mkdocstrings": "1.0.6",
    "mkdocstrings-python": "2.0.9",
    "msgpack": "1.2.3",
    "mypy": "1.20.2",
    "mypy-extensions": "1.1.0",
    "nodeenv": "1.11.0",
    "packageurl-python": "0.17.6",
    "packaging": "26.3",
    "paginate": "0.5.7",
    "pathspec": "1.1.1",
    "pip": "26.3",
    "pip-api": "0.0.35",
    "pip-audit": "2.10.1",
    "pip-requirements-parser": "32.0.1",
    "platformdirs": "4.12.2",
    "pluggy": "1.6.0",
    "poetry-core": "2.5.0",
    "pre-commit": "4.6.2",
    "py-serializable": "2.1.0",
    "pycryptodome": "3.24.0",
    "pygments": "2.21.0",
    "pymdown-extensions": "12.1",
    "pyparsing": "3.3.3",
    "pytest": "9.1.1",
    "pytest-cov": "7.1.0",
    "pytest-xdist": "3.8.0",
    "python-dateutil": "2.9.0.post0",
    "python-debian": "1.1.1",
    "python-discovery": "1.6.1",
    "python-magic": "0.4.27",
    "pyyaml": "6.0.3",
    "pyyaml-env-tag": "1.1",
    "referencing": "0.37.0",
    "requests": "2.34.2",
    "reuse": "6.2.0",
    "rfc3339-validator": "0.1.4",
    "rfc3986-validator": "0.1.1",
    "rfc3987-syntax": "1.1.0",
    "rfc8785": "0.1.4+emt.1",
    "rich": "15.0.0",
    "rpds-py": "2026.6.3",
    "ruff": "0.16.10",
    "six": "1.17.0",
    "sortedcontainers": "2.4.0",
    "stevedore": "5.9.1",
    "tomli": "2.4.1",
    "tomli-w": "1.2.0",
    "tomlkit": "0.15.1",
    "types-jsonschema": "4.26.0.20260518",
    "types-markdown": "3.10.2.20260712",
    "types-pyyaml": "6.0.12.20260906",
    "typing-extensions": "4.16.0",
    "tzdata": "2026.4",
    "uri-template": "1.3.0",
    "urllib3": "2.8.0",
    "uv": "0.13.7",
    "virtualenv": "21.15.6",
    "watchdog": "6.0.0",
    "webcolors": "25.10.0",
    "zizmor": "1.30.1",
}


NATIVE_TOOLS: Final = [
    {
        "role": "actionlint",
        "artifact_url": "https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz",
        "artifact_sha256": "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
        "bytes": 2353908,
        "binary_relative_path": ".tool-cache/native/actionlint/actionlint",
        "binary_sha256": "c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4",
    },
    {
        "role": "gitleaks",
        "artifact_url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "artifact_sha256": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        "bytes": 8230402,
        "binary_relative_path": ".tool-cache/native/gitleaks/gitleaks",
        "binary_sha256": "88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509",
    },
    {
        "role": "codeql",
        "artifact_url": "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.1/codeql-bundle-python-linux64.tar.zst",
        "artifact_sha256": "ea86393c6c812542ae5a3a7122bcc760873707a50b25cc47d2fd7cfd514b0cb0",
        "bytes": 111165259,
        "binary_relative_path": ".tool-cache/native/codeql/codeql/codeql",
        "binary_sha256": "5010324098d11f9e2d34e0fcf53bb44e40e8e3ffc8aecefe695269b54edaa413",
    },
]


AUDIT_SHA256: Final = "3bf24d1cc9e4d4448e1f48d85cc49636fa0fe980a022ad2c5ff93d850d695418"


AUDIT_PRODUCED_AT: Final = "2026-10-13T10:16:05.080220+00:00"


MKDOCS_SHA256: Final = "9a5ff4877cae96fdf8962db479a5cea795fcc6b314922843b98bc6112228ba7a"

DOCUMENTATION_TEMPLATE_SHA256: Final = (
    "b4b89ed459eaa0f1ed061fa76e4780df3f7c1c43ba05fca9cb8d0cff1dd38bbb"
)

DOCUMENTATION_FRAGMENT_HOOK_SHA256: Final = (
    "c441ee5f921ab848051ffac7dd276fbb2888f8e1322776f9aec175fd7349e61c"
)


PAYLOAD_API_NAMES: Final = frozenset(
    {
        "DvsEvent",
        "DvsGeometry",
        "LogicalEvent",
        "decode_dvs_columns",
        "encode_dvs_columns",
        "decode_logical_records",
        "encode_logical_records",
        "header_digest",
        "timed_chunk_digest",
        "metadata_chunk_digest",
        "fold_chain",
        "index_digest",
    }
)

PAYLOAD_API_SOURCE_SHA256: Final = {
    "src/spike_log/__init__.py": "63fe3edcd2af163b4eb28736956890d148f62e702bc50b3a39b0f37d164f1737",
    "src/spike_log/dvs_columns.py": "e702cb9cc62274f8b260e2784a5287048190c905510a3920ac391bd7887daa4c",
    "src/spike_log/logical_records.py": "4ef924e8ab67594af7025aedfbc631b1399671f6adba1637d26f84cf8a6dac0b",
    "src/spike_log/container_digests.py": "b6e5d718865235f910e6674dc3943b10fc06709f2ed007b94a5481823e7da354",
}
