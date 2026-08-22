"""Deploy this agent to Agent Runtime (validates manifest first)."""

import sys  # noqa: E402
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
for _p in (str(_ROOT), str(_ROOT / "packages")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from apps.agents._deploy import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(
        main(
            agent_module="apps.agents.treasury_approval.manifest",
            display_name="Treasury Approval Agent",
        )
    )
