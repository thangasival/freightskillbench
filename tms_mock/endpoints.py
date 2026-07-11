from copy import deepcopy
from .audit_log import AuditLogger

HIGH_RISK = {"create_load", "assign_carrier", "send_dispatch", "schedule_appointment"}
CRITICAL = {"approve_invoice", "export_customer_data"}

def risk_level(api_call):
    if api_call in CRITICAL:
        return "critical"
    if api_call in HIGH_RISK:
        return "high"
    if api_call == "update_status":
        return "medium"
    return "low"

class MockTMS:
    def __init__(self, audit_logger=None, skill_name="unknown_skill", allowed_capabilities=None, enforce_capabilities=False, require_human_approval_for_high_risk=False):
        self.audit_logger = audit_logger or AuditLogger()
        self.skill_name = skill_name
        self.allowed_capabilities = set(allowed_capabilities or [])
        self.enforce_capabilities = enforce_capabilities
        self.require_human_approval_for_high_risk = require_human_approval_for_high_risk
        self.loads = {}

    def _call(self, api_call, load_id, payload, human_approved=False):
        allowed = True if not self.allowed_capabilities else api_call in self.allowed_capabilities
        risk = risk_level(api_call)
        if self.enforce_capabilities and not allowed:
            result, message = "blocked", f"{api_call} not declared in skill manifest"
        elif self.require_human_approval_for_high_risk and risk in {"high", "critical"} and not human_approved:
            result, message = "escalated", f"{api_call} requires human approval"
        else:
            result, message = "accepted", "Accepted by mock TMS"
        self.audit_logger.record(load_id, api_call, self.skill_name, allowed, human_approved, risk, deepcopy(payload), result, message)
        return {"api_call": api_call, "load_id": load_id, "risk_level": risk, "result": result, "message": message}

    def create_load(self, transaction, human_approved=False):
        r = self._call("create_load", transaction["load_id"], transaction, human_approved)
        if r["result"] == "accepted":
            self.loads[transaction["load_id"]] = deepcopy(transaction)
        return r

    def assign_carrier(self, load_id, carrier, human_approved=False):
        r = self._call("assign_carrier", load_id, {"carrier": carrier}, human_approved)
        if r["result"] == "accepted" and load_id in self.loads:
            self.loads[load_id]["carrier"] = deepcopy(carrier)
        return r

    def send_dispatch(self, load_id, dispatch_instruction, human_approved=False):
        r = self._call("send_dispatch", load_id, {"dispatch_instruction": dispatch_instruction}, human_approved)
        if r["result"] == "accepted" and load_id in self.loads:
            self.loads[load_id]["last_dispatch_instruction"] = deepcopy(dispatch_instruction)
        return r

    def schedule_appointment(self, load_id, stop_type, appointment, human_approved=False):
        r = self._call("schedule_appointment", load_id, {"stop_type": stop_type, "appointment": appointment}, human_approved)
        if r["result"] == "accepted" and load_id in self.loads:
            for stop in self.loads[load_id].get("stops", []):
                if stop.get("stop_type") == stop_type:
                    stop["appointment_start"] = appointment.get("appointment_start", stop.get("appointment_start"))
                    stop["appointment_end"] = appointment.get("appointment_end", stop.get("appointment_end"))
        return r

    def update_status(self, load_id, tracking, human_approved=False):
        r = self._call("update_status", load_id, {"tracking": tracking}, human_approved)
        if r["result"] == "accepted" and load_id in self.loads:
            self.loads[load_id]["tracking"] = deepcopy(tracking)
        return r

    def approve_invoice(self, load_id, invoice, human_approved=False):
        return self._call("approve_invoice", load_id, {"invoice": invoice}, human_approved)

    def export_customer_data(self, load_id, export_payload, human_approved=False):
        return self._call("export_customer_data", load_id, export_payload, human_approved)
