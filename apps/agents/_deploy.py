"""Shared agent deployment helper.

Validates an agent manifest against the Control Plane's AgentManifest schema
and, when a Google Cloud project is configured, prints the Agent Runtime
deployment command. Deployment is intentionally explicit: agents are deployed
only when GOOGLE_CLOUD_PROJECT and DF_DEPLOY_CONFIRM=1 are set.

Usage (from the agent directory):
    python deploy.py
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[3]
for p in (str(_ROOT), str(_ROOT / "packages")):
    if p not in sys.path:
        sys.path.insert(0, p)

import yaml  # noqa: E402
from delegation_fabric_core.models.manifest import AgentManifest  # noqa: E402

REQUIRED_ENV_FOR_DEPLOY = ["GOOGLE_CLOUD_PROJECT", "DF_CONTROL_PLANE_URL"]


def load_manifest_data(module_name: str) -> dict[str, Any]:
    """Load the Python manifest dict and require agreement with its YAML twin.

    Every agent ships both ``manifest.py`` and ``manifest.yaml``. The Python
    module is the runtime source of truth; the YAML twin is what operators and
    tooling read. Deployment fails closed when the two drift apart.
    """
    module = importlib.import_module(module_name)
    data = getattr(module, "manifest", None)
    if not isinstance(data, dict):
        raise TypeError(f"{module_name} must expose a dict named 'manifest'")

    module_file = getattr(module, "__file__", None)
    if not module_file:
        return data
    yaml_path = Path(module_file).with_name("manifest.yaml")
    if not yaml_path.exists():
        raise FileNotFoundError(f"missing {yaml_path.name} twin for {module_name}")

    yaml_data = yaml.safe_load(yaml_path.read_text())
    if yaml_data != data:
        diff = sorted(k for k in set(data) | set(yaml_data) if data.get(k) != yaml_data.get(k))
        raise ValueError(
            f"manifest.yaml disagrees with manifest.py for {module_name}; differing keys: {diff}"
        )
    return data


def validate_manifest(module_name: str) -> AgentManifest:
    """Load manifest dict from module and validate it against the core schema."""
    data = load_manifest_data(module_name)
    return AgentManifest(
        agent_id=data["agent_id"],
        version=data["version"],
        display_name=data.get("display_name", ""),
        owner=data.get("owner", ""),
        risk_class=data["risk_class"],
        capabilities=data["capabilities"],
        denied_tools=data["denied_tools"],
        allowed_regions=data["allowed_regions"],
        memory=data.get("memory", {}),
    )


def main(agent_module: str, display_name: str) -> int:
    print(f"Validating manifest for {display_name}...")
    try:
        manifest = validate_manifest(agent_module)
    except Exception as e:
        print(f"FAIL: invalid agent manifest: {e}")
        return 1

    print(f"  OK  {manifest.agent_id}@{manifest.version}")
    print(f"      risk={manifest.risk_class.value} regions={manifest.allowed_regions}")
    print(f"      capabilities={manifest.capabilities}")
    print(f"      denied_tools={manifest.denied_tools}")

    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    region = os.environ.get("GOOGLE_CLOUD_LOCATION", "asia-south1")
    confirm = os.environ.get("DF_DEPLOY_CONFIRM") == "1"

    missing = [k for k in REQUIRED_ENV_FOR_DEPLOY if k.startswith("GOOGLE") and not project]
    if missing or not confirm:
        print("\nDRY RUN — deployment skipped.")
        if missing:
            print(f"  Missing env for real deploy: {missing}")
        if not confirm:
            print("  Set DF_DEPLOY_CONFIRM=1 to deploy to Agent Runtime.")
        print(
            f"\nTo deploy manually:\n"
            f"  gcloud ai agents create {manifest.agent_id} \\\n"
            f"    --project={project or '<PROJECT>'} --location={region} \\\n"
            f"    --display-name={display_name!r}"
        )
        return 0

    print(f"\nDeploying {manifest.agent_id} to Agent Runtime ({region})...")
    try:
        import subprocess

        result = subprocess.run(
            [
                "gcloud",
                "ai",
                "agents",
                "create",
                manifest.agent_id,
                f"--project={project}",
                f"--location={region}",
                f"--display-name={display_name}",
            ],
            check=False,
        )
        if result.returncode != 0:
            print("FAIL: gcloud deployment returned non-zero exit code.")
            return 1
    except FileNotFoundError:
        print("FAIL: gcloud CLI not found on PATH.")
        return 1

    print("OK: agent registered in Agent Registry.")
    return 0
