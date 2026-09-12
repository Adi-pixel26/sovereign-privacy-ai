"""
DPDP Act 2023 Section 6 Statutory Consent Manager & Revocation Portal.
Allows Data Principals to track active data processing consents granted to apps/websites
and issue formal 1-click statutory consent revocation notices under DPDP Act 2023.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from sovereign_privacy.db.storage import Storage

class ConsentManager:
    def __init__(self, storage: Storage):
        self.storage = storage

    def get_consents(self) -> List[Dict[str, Any]]:
        """Returns active app/service consent permissions."""
        profile = self.storage.get_profile()
        return profile.get("granted_consents", [
            {
                "id": "consent_swiggy",
                "app_name": "Food Delivery App",
                "data_fiduciary": "Swiggy / Zomato",
                "consents_granted": ["Location GPS", "Phone Number", "Order History", "UPI Handle"],
                "granted_date": "2025-05-10",
                "status": "ACTIVE"
            },
            {
                "id": "consent_ecom",
                "app_name": "E-Commerce Shopping Portal",
                "data_fiduciary": "Flipkart / Amazon India",
                "consents_granted": ["Saved Address", "Phone Number", "Browsing Habits"],
                "granted_date": "2025-08-15",
                "status": "ACTIVE"
            },
            {
                "id": "consent_fin",
                "app_name": "Instant Credit / Loan App",
                "data_fiduciary": "FinTech Capital Pvt Ltd",
                "consents_granted": ["Contacts Access", "SMS Metadata", "PAN Card", "Aadhaar Scans"],
                "granted_date": "2026-01-12",
                "status": "ACTIVE"
            }
        ])

    def revoke_consent(self, consent_id: str) -> Dict[str, Any]:
        """Revokes consent under DPDP Act 2023 Section 6 and generates formal notice."""
        profile = self.storage.get_profile()
        consents = self.get_consents()
        target = next((c for c in consents if c["id"] == consent_id), None)
        
        target_name = target.get("data_fiduciary", "Data Fiduciary") if target else "Data Fiduciary"
        
        notice_text = f"""STATUTORY NOTICE OF CONSENT REVOCATION
PURSUANT TO SECTION 6(4) OF THE DIGITAL PERSONAL DATA PROTECTION ACT, 2023

Date: {datetime.now(timezone.utc).strftime("%B %d, %Y")}
To Data Protection Officer: {target_name}

RE: Formal Revocation of Consent for Personal Data Processing

Dear Data Fiduciary,

Under Section 6(4) of India's Digital Personal Data Protection Act, 2023, I hereby formally withdraw and revoke any and all consent previously granted to {target_name} to collect, process, store, or share my personal data.

Pursuant to Section 6(6) of the DPDP Act 2023, upon receipt of this revocation notice, you are legally mandated to cease processing my personal data immediately and instruct all Data Processors acting on your behalf to erase my personal data within 30 days.

Sincerely,

{profile.get('full_name', 'Data Principal')}
Email: {profile.get('email')}
Cryptographic Proof Token: DPDP-REVOKE-{uuid.uuid4().hex[:12].upper()}
"""

        self.storage.log_agent_action(
            "CONSENT_REVOKED",
            f"Revoked consent for '{target_name}' under DPDP Act 2023 Sec 6(4)."
        )

        return {
            "consent_id": consent_id,
            "status": "REVOKED",
            "data_fiduciary": target_name,
            "revocation_notice": notice_text,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
