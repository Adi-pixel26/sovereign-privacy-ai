"""
Database & Persistence Layer for Sovereign Privacy Agent.
Supports persistent storage for identity targets, leak logs,
data broker registries, RTBF legal requests, anti-scraping honeytokens,
agent execution logs, and cryptographic SHA-256 audit chains.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from sovereign_privacy.core.audit_chain import AuditChain

STORAGE_FILE = os.path.join(os.path.dirname(__file__), "privacy_vault.json")

DEFAULT_BROKERS = [
    {
        "id": "signalhire",
        "name": "SignalHire (India & Global)",
        "domain": "signalhire.com",
        "category": "Contact & Phone Directory Aggregator",
        "opt_out_url": "https://www.signalhire.com/opt-out",
        "contact_email": "privacy@signalhire.com",
        "jurisdiction_support": ["DPDP", "GDPR", "CCPA"],
        "avg_response_days": 3,
        "opt_out_method": "DIRECT_EMAIL"
    },
    {
        "id": "lifesight",
        "name": "Lifesight (APAC / India)",
        "domain": "lifesight.io",
        "category": "Consumer Intelligence & Identity Graph",
        "opt_out_url": "https://www.lifesight.io/privacy-policy",
        "contact_email": "dpo@lifesight.io",
        "jurisdiction_support": ["DPDP", "GDPR"],
        "avg_response_days": 5,
        "opt_out_method": "FORMAL_NOTICE"
    },
    {
        "id": "telemarketer_registry",
        "name": "Indian Telemarketer Spam Registry",
        "domain": "trai.gov.in",
        "category": "Telecommunication & Call Directory",
        "opt_out_url": "https://telecomcommercialcom.trai.gov.in",
        "contact_email": "dnd@trai.gov.in",
        "jurisdiction_support": ["DPDP"],
        "avg_response_days": 2,
        "opt_out_method": "GOVT_PORTAL"
    },
    {
        "id": "acxiom",
        "name": "Acxiom Global",
        "domain": "acxiom.com",
        "category": "Data Broker & Marketing Intelligence",
        "opt_out_url": "https://iservice.acxiom.com/optout",
        "contact_email": "privacy@acxiom.com",
        "jurisdiction_support": ["DPDP", "GDPR", "CCPA", "PIPEDA"],
        "avg_response_days": 5,
        "opt_out_method": "EMAIL_FORM"
    },
    {
        "id": "spokeo",
        "name": "Spokeo",
        "domain": "spokeo.com",
        "category": "People Search Engine",
        "opt_out_url": "https://www.spokeo.com/optout",
        "contact_email": "privacy@spokeo.com",
        "jurisdiction_support": ["GDPR", "CCPA"],
        "avg_response_days": 3,
        "opt_out_method": "DIRECT_REQUEST"
    },
    {
        "id": "whitepages",
        "name": "Whitepages",
        "domain": "whitepages.com",
        "category": "Directory & Background Search",
        "opt_out_url": "https://www.whitepages.com/suppression-requests",
        "contact_email": "privacy@whitepages.com",
        "jurisdiction_support": ["CCPA"],
        "avg_response_days": 4,
        "opt_out_method": "SUPPRESSION_PORTAL"
    },
    {
        "id": "lexisnexis",
        "name": "LexisNexis Risk Solutions",
        "domain": "lexisnexis.com",
        "category": "Risk & Analytics Aggregator",
        "opt_out_url": "https://optout.lexisnexis.com",
        "contact_email": "privacy.inquiries@lexisnexis.com",
        "jurisdiction_support": ["DPDP", "GDPR", "CCPA"],
        "avg_response_days": 10,
        "opt_out_method": "FORMAL_NOTICE"
    }
]

class Storage:
    def __init__(self, filepath: str = STORAGE_FILE):
        self.filepath = filepath
        self.audit_chain = AuditChain()
        self._ensure_storage()

    def _ensure_storage(self):
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        if not os.path.exists(self.filepath) or os.path.getsize(self.filepath) == 0:
            initial_data = {
                "profile": {
                    "full_name": "Aarav Sharma",
                    "email": "aarav.sharma@example.com",
                    "secondary_emails": ["aarav.dev@techcorp.in"],
                    "phone": "+91-98765-43210",
                    "aadhaar_masked": "XXXX-XXXX-8901",
                    "pan_masked": "ABCPD1234E",
                    "upi_id": "aarav.sharma@ybl",
                    "jurisdiction": "DPDP",
                    "country": "India",
                    "state": "Delhi",
                    "autoremoval_enabled": True,
                    "risk_threshold": "MEDIUM"
                },
                "brokers": DEFAULT_BROKERS,
                "leaks": [],
                "rtbf_requests": [],
                "honeytokens": [],
                "identity_aliases": [],
                "agent_logs": [],
                "audit_blocks": self.audit_chain.chain
            }
            self._save_raw(initial_data)
        else:
            # Sync existing audit chain into memory if present
            raw = self._load_raw()
            if raw.get("audit_blocks"):
                self.audit_chain.chain = raw["audit_blocks"]

    def _load_raw(self) -> Dict[str, Any]:
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {
                "profile": {},
                "brokers": DEFAULT_BROKERS,
                "leaks": [],
                "rtbf_requests": [],
                "honeytokens": [],
                "identity_aliases": [],
                "agent_logs": [],
                "audit_blocks": []
            }

    def _save_raw(self, data: Dict[str, Any]):
        data["audit_blocks"] = self.audit_chain.chain
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # --- Profile Operations ---
    def get_profile(self) -> Dict[str, Any]:
        data = self._load_raw()
        return data.get("profile", {})

    def update_profile(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load_raw()
        data["profile"].update(updates)
        self._save_raw(data)
        self.log_agent_action("PROFILE_UPDATE", f"Updated user privacy profile for {data['profile'].get('email')}")
        return data["profile"]

    # --- Data Brokers ---
    def get_brokers(self) -> List[Dict[str, Any]]:
        data = self._load_raw()
        return data.get("brokers", [])

    def add_broker(self, broker: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load_raw()
        if "id" not in broker:
            broker["id"] = broker.get("name", "broker").lower().replace(" ", "_")
        data["brokers"].append(broker)
        self._save_raw(data)
        return broker

    # --- Data Leaks ---
    def get_leaks(self) -> List[Dict[str, Any]]:
        data = self._load_raw()
        return data.get("leaks", [])

    def add_leak(self, leak: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load_raw()
        if "id" not in leak:
            leak["id"] = str(uuid.uuid4())
        if "detected_at" not in leak:
            leak["detected_at"] = datetime.now(timezone.utc).isoformat()
        
        existing_ids = [l.get("title", "") + l.get("exposed_target", "") for l in data.get("leaks", [])]
        current_key = leak.get("title", "") + leak.get("exposed_target", "")
        if current_key not in existing_ids:
            data["leaks"].append(leak)
            self._save_raw(data)
            self.log_agent_action(
                "LEAK_DETECTED", 
                f"Data leak detected: '{leak.get('title')}' affecting target '{leak.get('exposed_target')}' (Severity: {leak.get('severity')})"
            )
        return leak

    def update_leak_status(self, leak_id: str, status: str) -> Optional[Dict[str, Any]]:
        data = self._load_raw()
        for leak in data.get("leaks", []):
            if leak.get("id") == leak_id:
                leak["status"] = status
                self._save_raw(data)
                return leak
        return None

    def delete_leak(self, leak_id: str) -> bool:
        data = self._load_raw()
        initial_len = len(data.get("leaks", []))
        data["leaks"] = [l for l in data.get("leaks", []) if l.get("id") != leak_id]
        if len(data["leaks"]) < initial_len:
            self._save_raw(data)
            self.log_agent_action("LEAK_DELETED", f"Deleted leak entry {leak_id}")
            return True
        return False

    # --- RTBF Legal Requests ---
    def get_rtbf_requests(self) -> List[Dict[str, Any]]:
        data = self._load_raw()
        return data.get("rtbf_requests", [])

    def add_rtbf_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load_raw()
        if "id" not in req:
            req["id"] = str(uuid.uuid4())
        if "created_at" not in req:
            req["created_at"] = datetime.now(timezone.utc).isoformat()
        if "status" not in req:
            req["status"] = "DRAFT"
        data["rtbf_requests"].append(req)
        self._save_raw(data)
        self.log_agent_action(
            "RTBF_CREATED", 
            f"Created RTBF Legal Request ID {req['id'][:8]} for '{req.get('target_entity')}' under {req.get('jurisdiction')}"
        )
        return req

    def update_rtbf_status(self, request_id: str, status: str, response_notes: str = "") -> Optional[Dict[str, Any]]:
        data = self._load_raw()
        for req in data.get("rtbf_requests", []):
            if req.get("id") == request_id:
                req["status"] = status
                req["updated_at"] = datetime.now(timezone.utc).isoformat()
                if response_notes:
                    req.setdefault("history", []).append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "status": status,
                        "notes": response_notes
                    })
                self._save_raw(data)
                self.log_agent_action(
                    "RTBF_STATUS_CHANGE",
                    f"RTBF Request {request_id[:8]} updated to status '{status}'"
                )
                return req
        return None

    # --- Honeytokens & Anti-Scraping ---
    def get_honeytokens(self) -> List[Dict[str, Any]]:
        data = self._load_raw()
        return data.get("honeytokens", [])

    def add_honeytoken(self, token: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load_raw()
        if "id" not in token:
            token["id"] = str(uuid.uuid4())
        if "created_at" not in token:
            token["created_at"] = datetime.now(timezone.utc).isoformat()
        token["triggers_count"] = token.get("triggers_count", 0)
        data["honeytokens"].append(token)
        self._save_raw(data)
        self.log_agent_action("HONEYTOKEN_CREATED", f"Deployed anti-scraping honeytoken ({token.get('token_type')})")
        return token

    def trigger_honeytoken(self, token_key: str, scraper_ip: str = "Unknown", user_agent: str = "Unknown") -> Optional[Dict[str, Any]]:
        data = self._load_raw()
        for token in data.get("honeytokens", []):
            if token.get("key") == token_key or token.get("id") == token_key:
                token["triggers_count"] += 1
                token["last_triggered"] = datetime.now(timezone.utc).isoformat()
                token.setdefault("trigger_logs", []).append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "ip": scraper_ip,
                    "user_agent": user_agent
                })
                self._save_raw(data)
                self.log_agent_action(
                    "SCRAPER_ALERT",
                    f"Honeytoken triggered by unauthorized scraper! IP: {scraper_ip}, Token: {token.get('label')}"
                )
                return token
        return None

    # --- Identity Aliases ---
    def get_aliases(self) -> List[Dict[str, Any]]:
        data = self._load_raw()
        return data.get("identity_aliases", [])

    def add_alias(self, alias: Dict[str, Any]) -> Dict[str, Any]:
        data = self._load_raw()
        if "id" not in alias:
            alias["id"] = str(uuid.uuid4())
        if "created_at" not in alias:
            alias["created_at"] = datetime.now(timezone.utc).isoformat()
        data["identity_aliases"].append(alias)
        self._save_raw(data)
        self.log_agent_action("ALIAS_CREATED", f"Created synthetic privacy alias '{alias.get('alias_email')}' for {alias.get('service_name')}")
        return alias

    # --- Cryptographic Audit Chain & Logs ---
    def get_agent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        data = self._load_raw()
        logs = data.get("agent_logs", [])
        return sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]

    def log_agent_action(self, action_type: str, message: str):
        data = self._load_raw()
        log_entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "message": message
        }
        data.setdefault("agent_logs", []).append(log_entry)
        
        # Add to SHA-256 block-linked audit chain
        self.audit_chain.add_receipt(action=action_type, data={"message": message, "timestamp": log_entry["timestamp"]})
        
        self._save_raw(data)
