"""
Top-level shim so the documented `python -m proofstrike scan <url>` works when run
from the backend/ directory (and `python proofstrike.py scan <url>` too).

The actual CLI lives in app/cli.py.
"""

from app.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
