"""Shared scaffolding for per-agent unit test suites.

Helpers here are parameterized over agent directory names so each agent's test
module only keeps its workflow-specific cases.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

FORBIDDEN_DB_ROOTS = frozenset({"sqlalchemy", "asyncpg", "psycopg", "psycopg2"})


def agent_paths(agent_dir_name: str) -> tuple[Path, str, str]:
    """Return (agent_dir, manifest_module, tools_module) for an agent directory."""
    root = Path(__file__).resolve().parents[3] / "apps" / "agents" / agent_dir_name
    dotted = f"apps.agents.{agent_dir_name}"
    return root, f"{dotted}.manifest", f"{dotted}.tools"


def load_manifest_dict(manifest_module: str) -> dict[str, object]:
    """Import the agent manifest module and return its ``manifest`` dict."""
    module = importlib.import_module(manifest_module)
    data: dict[str, object] = module.manifest
    return data


def forbidden_db_imports(agent_dir: Path) -> set[str]:
    """Collect DB driver imports via AST so sys.modules pollution cannot false-positive."""
    found: set[str] = set()
    for py_file in agent_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in FORBIDDEN_DB_ROOTS:
                        found.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                if root in FORBIDDEN_DB_ROOTS:
                    found.add(node.module)
    return found
