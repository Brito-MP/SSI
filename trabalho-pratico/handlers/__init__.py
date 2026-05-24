import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
CLIENT_DIR = ROOT_DIR / "client"
HANDLERS_DIR = CLIENT_DIR / "handlers"

for path in (ROOT_DIR, CLIENT_DIR):
    path_text = str(path)
    if path_text not in sys.path:
        sys.path.insert(0, path_text)

__path__ = [str(HANDLERS_DIR)]
