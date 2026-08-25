"""Manifest YAML/Python parity checks parameterized across all shipped agents."""

from __future__ import annotations

import pytest
import yaml

from tests.unit.agents.conftest import agent_paths, load_manifest_dict

AGENT_DIR_NAMES = [
    "invoice_reconciliation",
    "procurement_exception",
    "treasury_approval",
]


@pytest.mark.parametrize("agent_dir_name", AGENT_DIR_NAMES)
def test_manifest_yaml_matches_manifest_py(agent_dir_name: str) -> None:
    agent_dir, manifest_module, _tools_module = agent_paths(agent_dir_name)
    py_data = load_manifest_dict(manifest_module)
    yaml_data = yaml.safe_load((agent_dir / "manifest.yaml").read_text())
    assert yaml_data == py_data
