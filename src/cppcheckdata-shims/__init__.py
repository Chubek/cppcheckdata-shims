import sys
from pathlib import Path

extra_path = Path(__file__).resolve().parent.parent / "deps"

if str(extra_path) not in sys.path:
    sys.path.insert(0, str(extra_path))
