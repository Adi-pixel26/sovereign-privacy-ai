"""
Autonomous Agent Orchestrator.
Runs autonomous privacy defense loops: monitors leaks, auto-evaluates risk thresholds,
automatically drafts or dispatches RTBF legal notices, monitors honeytokens, and coordinates defenses.
"""

from typing import Dict, List, Any
from sovereign_privacy.db.storage import Storage
from sovereign_privacy.core.leak_monitor import LeakMonitor
from sovereign_privacy.core.rtbf_agent import RTBFAgent
from sovereign_privacy.core.anti_scraper import AntiScraper
from sovereign_privacy.core.identity_masker import IdentityMasker

class PrivacyOrchestrator:
    def __init__(self, storage: Storage = None):
        self.storage = storage or Storage()
        self.leak_monitor = LeakMonitor(self.storage)
        self.rtbf_agent = RTBFAgent(self.storage)
        self.anti_scraper = AntiScraper(self.storage)
        self.identity_masker = IdentityMasker(self.storage)

    def execute_autonomous_defense_cycle(self) -> Dict[str, Any]:
        """
        Executes a complete autonomous agent cycle:
        1. Run full leak scan.
        2. Evaluate newly discovered breach risks.
        3. If autoremoval enabled, auto-generate & dispatch RTBF requests for high-risk targets.
        4. Auto-check honeytoken status.
        5. Compile executive agent status report.
        """
        self.storage.log_agent_action("AGENT_CYCLE_START", "Autonomous Sovereign Privacy Agent cycle initiated.")
        
        profile = self.storage.get_profile()
        autoremoval = profile.get("autoremoval_enabled", True)
        jurisdiction = profile.get("jurisdiction", "GDPR")

        # 1. Leak Scan
        scan_results = self.leak_monitor.run_full_scan()
        unresolved_leaks = [l for l in scan_results.get("leaks", []) if l.get("status") == "UNRESOLVED"]

        auto_action_count = 0
        generated_requests = []

        # 2. Evaluate auto-remediation
        for leak in unresolved_leaks:
            severity = leak.get("severity", "MEDIUM").upper()
            domain = leak.get("domain", "Unknown Entity")

            if autoremoval and severity in ["CRITICAL", "HIGH"]:
                # Check if request already exists for this domain
                existing_reqs = self.storage.get_rtbf_requests()
                already_requested = any(r.get("target_entity") == domain for r in existing_reqs)

                if not already_requested:
                    new_req = self.rtbf_agent.create_request(
                        target_entity=domain,
                        target_contact=f"privacy@{domain}",
                        jurisdiction=jurisdiction,
                        custom_notes=f"AUTONOMOUS AGENT ACTION: Triggered by detection of {severity} data leak '{leak.get('title')}'."
                    )
                    # Auto-dispatch if critical
                    if severity == "CRITICAL":
                        dispatched = self.rtbf_agent.dispatch_request(new_req["id"])
                        if dispatched:
                            new_req = dispatched
                    
                    generated_requests.append(new_req)
                    auto_action_count += 1

        # 3. Check Honeytokens
        honeytokens = self.storage.get_honeytokens()
        triggered_tokens = [t for t in honeytokens if t.get("triggers_count", 0) > 0]

        summary = {
            "agent_status": "ONLINE_PROTECTED",
            "privacy_health_score": scan_results["privacy_health_score"],
            "rating": scan_results["rating"],
            "scanned_targets": scan_results["scanned_targets"],
            "total_breaches_detected": scan_results["total_leaks"],
            "unresolved_breaches": len(unresolved_leaks),
            "autonomous_actions_executed": auto_action_count,
            "new_rtbf_requests_generated": generated_requests,
            "active_honeytokens_deployed": len(honeytokens),
            "honeytokens_triggered": len(triggered_tokens)
        }

        self.storage.log_agent_action(
            "AGENT_CYCLE_COMPLETE",
            f"Autonomous defense cycle finished. Health Score: {summary['privacy_health_score']}/100. Autonomous RTBF requests created: {auto_action_count}."
        )

        return summary
