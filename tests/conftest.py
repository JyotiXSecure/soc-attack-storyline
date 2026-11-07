"""Make the project root importable so tests can use `from src...`."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
root_str = str(PROJECT_ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)
