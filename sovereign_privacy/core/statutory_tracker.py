"""
Statutory Compliance & Deadline Tracker.
Tracks legal response deadlines under:
- India DPDP Act 2023 (Section 12/13 — 30 Days Statutory Limit)
- EU GDPR (Article 12(3) — 30 Days Statutory Limit)
- California CCPA/CPRA (11 CCR §7022 — 45 Days Statutory Limit)
Calculates compliance progress, countdown days remaining, and statutory breach warnings.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

DEADLINE_DAYS = {
    "DPDP": 30,
    "GDPR": 30,
    "CCPA": 45,
    "PIPEDA": 30,
    "GENERIC": 30
}

class StatutoryTracker:
    def __init__(self, storage=None):
        self.storage = storage

    def calculate_deadline(self, created_at_iso: str, jurisdiction: str) -> Dict[str, Any]:
        """Calculates statutory deadline, days remaining, and compliance status."""
        try:
            created_dt = datetime.fromisoformat(created_at_iso)
        except Exception:
            created_dt = datetime.now(timezone.utc)

        days_limit = DEADLINE_DAYS.get(jurisdiction.upper(), 30)
        deadline_dt = created_dt + timedelta(days=days_limit)
        now_dt = datetime.now(timezone.utc)

        seconds_remaining = (deadline_dt - now_dt).total_seconds()
        days_remaining = max(0, int(seconds_remaining // 86400))
        is_overdue = seconds_remaining < 0

        if is_overdue:
            status_summary = "STATUTORY_DEADLINE_BREACHED"
        elif days_remaining <= 5:
            status_summary = "CRITICAL_DEADLINE_APPROACHING"
        elif days_remaining <= 15:
            status_summary = "IN_PROGRESS_MONITORING"
        else:
            status_summary = "ON_SCHEDULE"

        return {
            "jurisdiction": jurisdiction.upper(),
            "statutory_days_limit": days_limit,
            "created_at": created_dt.isoformat(),
            "deadline_date": deadline_dt.isoformat(),
            "days_remaining": days_remaining,
            "is_overdue": is_overdue,
            "status_summary": status_summary
        }

    def generate_milestones(self, jurisdiction: str, request_status: str) -> List[Dict[str, Any]]:
        """Generates standard legal compliance progress milestones."""
        milestones = [
            {"step": 1, "title": "Legal Notice Drafted", "status": "COMPLETED"},
            {"step": 2, "title": "Dispatched to Data Fiduciary", "status": "COMPLETED" if request_status != "DRAFT" else "PENDING"},
            {"step": 3, "title": "Statutory Acknowledgment", "status": "COMPLETED" if request_status in ["ACKNOWLEDGED", "IN_PROGRESS", "VERIFIED_REMOVED"] else "PENDING"},
            {"step": 4, "title": "PII Erasure Verification", "status": "COMPLETED" if request_status == "VERIFIED_REMOVED" else "PENDING"},
            {"step": 5, "title": "Cryptographic Audit Receipt Issued", "status": "COMPLETED" if request_status == "VERIFIED_REMOVED" else "PENDING"}
        ]
        return milestones
