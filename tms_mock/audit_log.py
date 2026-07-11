from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json, uuid

@dataclass
class AuditEvent:
    event_id: str
    timestamp_utc: str
    load_id: str
    api_call: str
    skill_name: str
    allowed_by_manifest: bool
    approved_by_human: bool
    risk_level: str
    payload: dict
    result: str
    message: str = ""

class AuditLogger:
    def __init__(self, output_path=None):
        self.events = []
        self.output_path = Path(output_path) if output_path else None

    def record(self, load_id, api_call, skill_name, allowed_by_manifest, approved_by_human, risk_level, payload, result, message=""):
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            load_id=load_id,
            api_call=api_call,
            skill_name=skill_name,
            allowed_by_manifest=allowed_by_manifest,
            approved_by_human=approved_by_human,
            risk_level=risk_level,
            payload=payload,
            result=result,
            message=message,
        )
        self.events.append(event)
        return event

    def to_dicts(self):
        return [asdict(e) for e in self.events]

    def write_jsonl(self, path=None):
        out = Path(path) if path else self.output_path
        if out is None:
            raise ValueError("No output path supplied.")
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as f:
            for e in self.to_dicts():
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        return out
