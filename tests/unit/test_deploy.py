"""Unit tests for apps.agents._deploy manifest loading and validation."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from apps.agents._deploy import load_manifest_data, validate_manifest

MANIFEST_PY = """\
manifest = {
    "agent_id": "fake-agent",
    "version": "1.0.0",
    "risk_class": "medium",
    "capabilities": ["invoice.read"],
    "denied_tools": [],
    "allowed_regions": ["asia-south1"],
}
"""

MANIFEST_YAML = """\
agent_id: fake-agent
version: 1.0.0
risk_class: medium
capabilities:
  - invoice.read
denied_tools: []
allowed_regions:
  - asia-south1
"""


@pytest.fixture
def make_agent_pkg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., str]:
    """Factory writing a fake agent package; returns its manifest module name."""

    def factory(
        name: str,
        *,
        manifest_py: str | None = MANIFEST_PY,
        yaml_text: str | None = MANIFEST_YAML,
    ) -> str:
        monkeypatch.syspath_prepend(str(tmp_path))
        pkg = tmp_path / name
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        if manifest_py is not None:
            (pkg / "manifest.py").write_text(manifest_py)
        if yaml_text is not None:
            (pkg / "manifest.yaml").write_text(yaml_text)
        return f"{name}.manifest"

    return factory


def test_load_manifest_data_parity_ok(make_agent_pkg: Callable[..., str]) -> None:
    module_name = make_agent_pkg("parity_ok")
    data = load_manifest_data(module_name)
    assert data == {
        "agent_id": "fake-agent",
        "version": "1.0.0",
        "risk_class": "medium",
        "capabilities": ["invoice.read"],
        "denied_tools": [],
        "allowed_regions": ["asia-south1"],
    }


def test_drifted_value_raises_with_differing_keys(
    make_agent_pkg: Callable[..., str],
) -> None:
    drifted_yaml = MANIFEST_YAML.replace("version: 1.0.0", "version: 9.9.9")
    module_name = make_agent_pkg("drifted", yaml_text=drifted_yaml)
    with pytest.raises(ValueError) as excinfo:
        load_manifest_data(module_name)
    assert "'version'" in str(excinfo.value)
    assert "differing keys" in str(excinfo.value)


def test_missing_yaml_twin_raises(make_agent_pkg: Callable[..., str]) -> None:
    module_name = make_agent_pkg("no_yaml", yaml_text=None)
    with pytest.raises(FileNotFoundError, match="missing manifest.yaml twin"):
        load_manifest_data(module_name)


def test_non_dict_yaml_raises(make_agent_pkg: Callable[..., str]) -> None:
    module_name = make_agent_pkg("list_yaml", yaml_text="- just\n- a\n- list\n")
    with pytest.raises(ValueError, match="not a mapping"):
        load_manifest_data(module_name)


def test_missing_manifest_attribute_raises(make_agent_pkg: Callable[..., str]) -> None:
    module_name = make_agent_pkg("no_attr", manifest_py="OTHER = {}\n")
    with pytest.raises(TypeError, match="must expose a dict named 'manifest'"):
        load_manifest_data(module_name)


def test_validate_manifest_builds_core_schema(
    make_agent_pkg: Callable[..., str],
) -> None:
    module_name = make_agent_pkg("valid_model")
    manifest = validate_manifest(module_name)
    assert manifest.agent_id == "fake-agent"
    assert manifest.risk_class.value == "medium"
    assert manifest.can_request_tool("invoice.read")


def test_validate_manifest_surfaces_unknown_keys(
    make_agent_pkg: Callable[..., str],
) -> None:
    py_with_rogue = MANIFEST_PY.replace(
        '    "allowed_regions"', '    "rogue_key": True,\n    "allowed_regions"'
    )
    yaml_with_rogue = MANIFEST_YAML.replace("allowed_regions:", "rogue_key: true\nallowed_regions:")
    module_name = make_agent_pkg(
        "unknown_key", manifest_py=py_with_rogue, yaml_text=yaml_with_rogue
    )
    with pytest.raises(ValueError, match="unknown manifest keys.*rogue_key"):
        validate_manifest(module_name)
