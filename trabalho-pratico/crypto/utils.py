import uuid
from datetime import datetime, timezone

def generate_message_id() -> str:
    return str(uuid.uuid4())

def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
