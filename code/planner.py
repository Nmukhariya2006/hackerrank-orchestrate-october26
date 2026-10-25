M = {"account": "account_service", "search": "search_service", "support": "support_platform",
          "analytics": "analytics_platform", "export": "export_service", "backup": "backup_service",
          "data_flow": "integration_service", "audit_record": "security_service",
          "tombstone": "identity_service", "marketing": "marketing_platform", "cache": "cache_service",
          "object": "object_storage", "legal_hold": "legal_service"}
ORD_F = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
ORD_R = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
ORD_V = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
         "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
STATE = {"REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
         "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
         "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
         "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
         "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
         "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
         "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED"}
#            finding,                   remediation,       verification
MAP = {"DELETE":   ("REPORT_REMAINING_RECORD", "DELETE_RECORD",   "VERIFY_RECORD_ABSENT"),
       "REDACT":   ("REPORT_EXPOSED_PII",      "REDACT_RECORD",   "VERIFY_RECORD_REDACTED"),
       "ANONYMIZE":("REPORT_EXPOSED_PII",      "ANONYMIZE_RECORD","VERIFY_RECORD_ANONYMIZED"),
       "FLOW":     ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW","VERIFY_DATA_FLOW_DISABLED"),
       "RESTORE":  ("REPORT_RESTORE_RISK",     "BLOCK_RESTORE",   "VERIFY_RESTORE_BLOCKED"),
       "RETAIN":   (None, None, "VERIFY_RECORD_PRESENT")}

def _sys(rid): 
    return M[rid.rsplit("_", 1)[0]]

def plan(resources, evidence_id):
    """resources: {rid: (treatment, compliant)} -> (status, steps)"""
    f, r, v = [], [], []
    incomplete = any(not ok for _, ok in resources.values())
    for rid, (tr, ok) in resources.items():
        fo, ro, vo = MAP[tr]
        if not ok:
            f.append((fo, rid)); r.append((ro, rid))
        v.append((vo, rid))
    key = lambda o, order: (order.index(o[0]), _sys(o[1]), o[1])
    steps = []
    def add(phase, items, order, ev):
        for op, rid in sorted(items, key=lambda x: key(x, order)):
            steps.append({"step_no": len(steps) + 1, "phase": phase, "system_id": _sys(rid),
                          "resource_id": rid, "operation": op, "state": STATE[op],
                          "evidence_id": ev if phase == "FINDING" or not incomplete else ""})
    if incomplete:
        add("FINDING", f, ORD_F, evidence_id)
        add("REMEDIATION", r, ORD_R, "")
        add("VERIFICATION", v, ORD_V, "")
        return "INCOMPLETE", steps
    add("VERIFICATION", v, ORD_V, evidence_id)
    return "COMPLETE", steps