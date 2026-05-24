import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
root_text = str(ROOT_DIR)
if root_text not in sys.path:
    sys.path.insert(0, root_text)
