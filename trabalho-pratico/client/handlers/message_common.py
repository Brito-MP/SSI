import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

GROUP_ACTION_DELETE = "delete"
GROUP_ACTION_LEAVE = "leave"
GROUP_ACTION_MESSAGE = "message"
GROUP_ACTION_KEY_ROTATION = "key_rotation"
GROUP_CONTROL_TYPE = "group_control"
GROUP_ROTATION_PENDING_FIELD = "group_key_rotation_pending"
GROUP_ROTATION_LEADER_FIELD = "group_key_rotation_leader"


def parse_json_object(text):
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data
