from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """Resolve the target repository root.

    MCP integrations should set SECURETRACE_PROJECT_ROOT or configure the
    MCP process working directory to the target repository.
    """
    configured = os.environ.get("SECURETRACE_PROJECT_ROOT")
    root = Path(configured).expanduser() if configured else Path.cwd()
    return root.resolve()
