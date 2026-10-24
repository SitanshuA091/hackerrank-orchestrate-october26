from dataclasses import dataclass

from ghost_audit.rules import OPS, VERIFY_STATE
from ghost_audit.state import ResState

PHASES = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]
RANK = {operation: index for index, operation in enumerate(ORDER)}


@dataclass
class Entry:
    resource_id: str
    system: str
    category: str
    action: str
    bad: bool
    state: ResState


def plan(entries, complete):
    rows = []
    for entry in entries:
        find_op, find_state, fix_op, fix_state, verify_op = OPS[entry.action]
        if entry.bad:
            rows.append(("FINDING", find_op, entry, find_state, entry.state.cite_present))
            rows.append(("REMEDIATION", fix_op, entry, fix_state, ""))
        evidence = ""
        if complete:
            evidence = entry.state.cite_absent if entry.action == "DELETE" else entry.state.cite_present
        rows.append(("VERIFICATION", verify_op, entry, VERIFY_STATE[entry.action], evidence))
    rows.sort(key=lambda row: (PHASES[row[0]], RANK[row[1]], row[2].system, row[2].resource_id))
    return [
        {
            "step_no": number,
            "phase": phase,
            "system_id": entry.system,
            "resource_id": entry.resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence,
        }
        for number, (phase, operation, entry, state, evidence) in enumerate(rows, 1)
    ]