import os
import json
import uuid
from datetime import datetime, timezone

DATA_DIR = "./data"
TRIAGE_FILE = os.path.join(DATA_DIR, "triage_log.json")

def _atomic_write(filepath: str, data: list):
    """Safely writes data using a temporary file to prevent corruption."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    tmp_path = filepath + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, filepath)

def load_triage_records() -> list:
    """Loads existing triage records from the data store."""
    if not os.path.exists(TRIAGE_FILE):
        return []
    with open(TRIAGE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_triage_record(record: dict):
    """Upserts a single triage record."""
    records = load_triage_records()
    
    # Check if record for this event already exists
    existing_idx = next((i for i, r in enumerate(records) if r.get("event_uid") == record.get("event_uid")), None)
    
    now = datetime.now(timezone.utc).isoformat()
    if existing_idx is not None:
        records[existing_idx].update(record)
        records[existing_idx]["updated_at"] = now
        records[existing_idx]["version"] = records[existing_idx].get("version", 1) + 1
    else:
        record["id"] = str(uuid.uuid4())[:8]
        record["created_at"] = now
        record["updated_at"] = now
        record["version"] = 1
        record["status"] = "active"
        records.append(record)
        
    _atomic_write(TRIAGE_FILE, records)