"""Entry point so `python -m app ...` runs the ProofStrike CLI."""

from app.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
