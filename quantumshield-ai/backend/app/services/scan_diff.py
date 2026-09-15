"""
QuantumShield Services — Scan Diff & Regression Tracker
Computes delta analysis between consecutive scans:
- New findings (+)
- Fixed / Remediated findings (-)
- Persistent findings (=)
- Severity mutations (escalated / downgraded)
"""

from typing import Any, Dict, List, Optional
from app.database.models import Finding, FindingStatus


def compute_scan_diff(
    current_findings: List[Finding],
    previous_findings: List[Finding]
) -> Dict[str, Any]:
    """
    Compare two scans and generate a structured diff summary.
    """
    prev_map = {f"{f.finding_type}:{f.endpoint}": f for f in previous_findings}
    curr_map = {f"{f.finding_type}:{f.endpoint}": f for f in current_findings}

    new_findings = []
    fixed_findings = []
    persistent_findings = []
    severity_changes = []

    # Detect new and persistent findings
    for key, curr_f in curr_map.items():
        curr_is_fixed = getattr(curr_f, "status", None) in (FindingStatus.FIXED, "FIXED", "REMEDIATED")
        if curr_is_fixed:
            fixed_findings.append({
                "id": curr_f.id,
                "title": curr_f.title,
                "type": curr_f.finding_type,
                "severity": curr_f.severity.value if hasattr(curr_f.severity, "value") else str(curr_f.severity),
                "endpoint": curr_f.endpoint,
                "status": "FIXED",
            })
            continue

        if key not in prev_map:
            new_findings.append({
                "id": curr_f.id,
                "title": curr_f.title,
                "type": curr_f.finding_type,
                "severity": curr_f.severity.value if hasattr(curr_f.severity, "value") else str(curr_f.severity),
                "endpoint": curr_f.endpoint,
                "status": "NEW",
            })
        else:
            prev_f = prev_map[key]
            prev_sev = prev_f.severity.value if hasattr(prev_f.severity, "value") else str(prev_f.severity)
            curr_sev = curr_f.severity.value if hasattr(curr_f.severity, "value") else str(curr_f.severity)

            if prev_sev != curr_sev:
                severity_changes.append({
                    "id": curr_f.id,
                    "title": curr_f.title,
                    "endpoint": curr_f.endpoint,
                    "old_severity": prev_sev,
                    "new_severity": curr_sev,
                })
            persistent_findings.append({
                "id": curr_f.id,
                "title": curr_f.title,
                "type": curr_f.finding_type,
                "severity": curr_sev,
                "endpoint": curr_f.endpoint,
                "status": "PERSISTENT",
            })

    # Detect fixed findings (present in previous scan, absent in current scan)
    for key, prev_f in prev_map.items():
        if key not in curr_map:
            fixed_findings.append({
                "id": prev_f.id,
                "title": prev_f.title,
                "type": prev_f.finding_type,
                "severity": prev_f.severity.value if hasattr(prev_f.severity, "value") else str(prev_f.severity),
                "endpoint": prev_f.endpoint,
                "status": "FIXED",
            })

    return {
        "summary": {
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "persistent_count": len(persistent_findings),
            "severity_change_count": len(severity_changes),
            "net_risk_delta": f"{'-' if len(fixed_findings) >= len(new_findings) else '+'}{abs(len(fixed_findings) - len(new_findings))}",
        },
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "persistent_findings": persistent_findings,
        "severity_changes": severity_changes,
    }
