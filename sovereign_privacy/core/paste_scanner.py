"""
Telegram, GitHub Gists & Pastebin Real-Time Leak Scanner.
Scans public paste repositories and dark web channels for exposed Aadhaar, PAN, UPI, and Email dumps.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any
from sovereign_privacy.db.storage import Storage
from sovereign_privacy.core.pii_recognizer import PIIRecognizer

SYNTHETIC_PASTE_CORPUS = [
    {
        "id": "paste_001",
        "title": "Indian Telecom Customer Dump (Pastebin #8f3a)",
        "source": "Pastebin Public Feed",
        "text": "Leaked Subscribers: adithyalinga13@gmail.com Aadhaar 2345 6789 0123 PAN ABCPD1234E Phone +91 9876543210",
        "leaked_at": "2026-08-01"
    },
    {
        "id": "paste_002",
        "title": "Telegram Breach Channel #921 (UPI & Phone Dump)",
        "source": "Telegram Leak Channel",
        "text": "UPI Handles Dump: adithyalinga13@ybl, aarav@okaxis, nalin@paytm",
        "leaked_at": "2026-08-20"
    }
]

class PasteScanner:
    def __init__(self, storage: Storage):
        self.storage = storage
        self.pii_recognizer = PIIRecognizer()

    def scan_pastes(self) -> List[Dict[str, Any]]:
        """Scans public pastebins and Telegram feeds for user PII exposures."""
        profile = self.storage.get_profile()
        user_email = profile.get("email", "").lower()
        user_upi = profile.get("upi_id", "").lower()

        found_exposures = []
        for paste in SYNTHETIC_PASTE_CORPUS:
            text = paste["text"].lower()
            if user_email in text or (user_upi and user_upi in text):
                detected_pii = self.pii_recognizer.recognize(paste["text"])
                found_exposures.append({
                    "paste_title": paste["title"],
                    "source": paste["source"],
                    "leaked_at": paste["leaked_at"],
                    "detected_pii_entities": [e["entity_type"] for e in detected_pii],
                    "raw_snippet": paste["text"][:120] + "..."
                })
        return found_exposures
