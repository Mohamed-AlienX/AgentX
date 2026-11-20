"""Annotate skill frontmatter with ``mitre_attack`` from the reviewed mapping.

Usage:
    python scripts/annotate_mitre.py           # apply
    python scripts/annotate_mitre.py --check   # exit 1 if any skill is stale
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentx.mitre_annotate import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
