# SPDX-License-Identifier: AGPL-3.0-or-later
# Commercial license available
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# SPIKE-LOG — source and configuration provenance

"""Strict bounded YAML parsing loaded only inside the guarded operation."""

from __future__ import annotations

import re

import yaml

from .inputs import Json, decode, require_byte_budget, validate_value
from .policy import MAX_DEPTH, MAX_INPUT, MAX_VALUES
from .reports import Fault


class LocalYamlLoader(yaml.SafeLoader):
    """Preserve GitHub's 'on' key and reject duplicate/merged YAML members."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[object, object]:
        """Construct a unique mapping; merge keys cannot select hidden policy.

        Parameters
        ----------
        node : yaml.MappingNode
            Native mapping node whose merge tags, key kinds and uniqueness are inspected.
        deep : bool
            Native SafeLoader construction flag forwarded to each admitted key/value.

        Returns
        -------
        dict[object, object]
            Unique native constructed members, subsequently narrowed by the public finite JSON-value validator.

        Raises
        ------
        Fault
            Raised for a merge tag, unsupported key kind or duplicate key.
        """
        output: dict[object, object] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise Fault("workflow_policy.yaml-alias")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, (str, bool, int, float)):
                raise Fault("policy_refusal")
            if key in output:
                raise Fault("duplicate_member")
            output[key] = self.construct_object(value_node, deep=deep)
        return output


LocalYamlLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
LocalYamlLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.IGNORECASE), list("tTfF")
)


def parse_yaml(data: bytes, name: str, workflow: bool = False) -> dict[str, Json]:
    """Parse one retained bounded byte string with the same strict YAML contract.

    Parameters
    ----------
    data : bytes
        Original safe-YAML bytes bounded before native token events/construction.
    name : str
        Safe lexical location used for authored parser diagnostics.
    workflow : bool
        Enable the tighter workflow byte/line limits while retaining alias/tag/duplicate controls.

    Returns
    -------
    dict[str, Json]
        Finite string-keyed mapping admitted without unsafe constructors, anchors, merges or duplicate members.

    Raises
    ------
    Fault
        Raised for input/resource/Unicode/syntax/tag/alias/duplicate or mapping-shape refusal.
    """
    require_byte_budget(len(data), 102400 if workflow else MAX_INPUT, name)
    text = decode(data, name)
    if workflow and len(text.splitlines()) > 1000:
        raise Fault("workflow_policy.size-limit", name)
    depth, count = 0, 0
    try:
        for event in yaml.parse(text):
            if isinstance(
                event, (yaml.ScalarEvent, yaml.MappingStartEvent, yaml.SequenceStartEvent)
            ):
                count += 1
            if isinstance(event, (yaml.AliasEvent,)) or getattr(event, "anchor", None):
                raise Fault("workflow_policy.yaml-alias", name)
            tag = getattr(event, "tag", None)
            if tag and tag not in {
                "tag:yaml.org,2002:str",
                "tag:yaml.org,2002:int",
                "tag:yaml.org,2002:float",
                "tag:yaml.org,2002:bool",
                "tag:yaml.org,2002:null",
                "tag:yaml.org,2002:seq",
                "tag:yaml.org,2002:map",
            }:
                raise Fault("workflow_policy.yaml-alias", name)
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if depth > MAX_DEPTH or count > MAX_VALUES:
                raise Fault("resource_limit", name)
        loader = LocalYamlLoader(text)
        try:
            value: object = loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError as error:
        raise Fault("policy_refusal", name) from error
    result = validate_value(value, name)
    if not isinstance(result, dict):
        raise Fault("policy_refusal", name)
    return result
