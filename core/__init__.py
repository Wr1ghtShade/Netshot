"""NetShot application code. Entry points: netshot.py (command line) and netshot_gui.py (GUI)."""

from pathlib import Path

# Application folder (holds keys.json, assets/, screenshots/)
ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
