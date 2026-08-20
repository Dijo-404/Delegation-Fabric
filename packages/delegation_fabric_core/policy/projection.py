"""Response field projection engine.

Filters response payloads so only explicitly allowed fields reach the agent.
Supports:
- Top-level fields: 'status', 'total_minor'
- Nested fields: 'vendor.legal_name'
- Lists of dicts: 'lines.line_no', 'lines.description'
- Missing allow-list / empty allow-list -> empty result or empty projection
- Unknown or non-allowed fields are silently dropped
"""

from __future__ import annotations

from typing import Any

from delegation_fabric_core.models.policy import JsonValue, ProjectionResult


def _build_projection_tree(allowed_paths: list[str]) -> dict[str, Any]:
    """Parse dot paths into a nested tree structure for filtering."""
    tree: dict[str, Any] = {}
    for path in allowed_paths:
        if not path:
            continue
        parts = path.split(".")
        current = tree
        for part in parts:
            if part not in current:
                current[part] = {}
            current = current[part]
    return tree


def _project_recursive(
    data: Any,
    tree: dict[str, Any],
) -> tuple[Any, int]:
    """Recursively filter `data` according to `tree` structure.

    Returns (projected_data, dropped_count).
    """
    if isinstance(data, dict):
        if not tree:
            # If tree is empty at this node, but path reached here, retain entire dict
            # or if root tree was empty, project nothing
            return {}, len(data)

        result: dict[str, Any] = {}
        dropped = 0
        for key, value in data.items():
            if key in tree:
                sub_tree = tree[key]
                if sub_tree:
                    sub_val, sub_dropped = _project_recursive(value, sub_tree)
                    result[key] = sub_val
                    dropped += sub_dropped
                else:
                    # Leaf in allowed paths -> keep full sub-value
                    result[key] = value
            else:
                dropped += 1
        return result, dropped

    elif isinstance(data, list):
        result_list = []
        total_dropped = 0
        for item in data:
            if isinstance(item, (dict, list)):
                sub_val, sub_dropped = _project_recursive(item, tree)
                result_list.append(sub_val)
                total_dropped += sub_dropped
            else:
                # Scalar item in list
                result_list.append(item)
        return result_list, total_dropped

    else:
        return data, 0


def project_fields(
    payload: JsonValue,
    allowed_paths: list[str],
) -> ProjectionResult:
    """Project only allowed fields from payload.

    If allowed_paths is empty, returns empty object or empty list with dropped count.
    """
    if not allowed_paths:
        if isinstance(payload, dict):
            return ProjectionResult(projected={}, dropped_count=len(payload))
        elif isinstance(payload, list):
            return ProjectionResult(projected=[], dropped_count=len(payload))
        return ProjectionResult(projected=None, dropped_count=1)

    tree = _build_projection_tree(allowed_paths)
    projected, dropped = _project_recursive(payload, tree)
    return ProjectionResult(projected=projected, dropped_count=dropped)
