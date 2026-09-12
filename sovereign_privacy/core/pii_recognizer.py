"""
PII Recognizer & Strict Identity Cross-Verification Module.
Includes Aadhaar (Verhoeff checksum validation), PAN Card format matching,
UPI ID matching, Indian Mobile Numbers (+91), Emails, IP addresses, and Credit Cards.
Also compares detected PII against the user's profile to flag Third-Party or Impersonated PII.
"""

import re
from typing import List, Dict, Any, Optional

# ── Verhoeff Algorithm for Aadhaar Validation ──
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 6, 7, 8, 9, 0, 1, 2, 3, 4],
    [6, 7, 8, 9, 5, 1, 2, 3, 4, 0],
    [7, 8, 9, 5, 6, 2, 3, 4, 0, 1],
    [8, 9, 5, 6, 7, 3, 4, 0, 1, 2],
    [9, 5, 6, 7, 8, 4, 0, 1, 2, 3]
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def verhoeff_validate(number_str: str) -> bool:
    clean = re.sub(r'\D', '', number_str)
    if len(clean) != 12 or clean.startswith('0') or clean.startswith('1'):
        return False
    c = 0
    for i, item in enumerate(reversed(clean)):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][int(item)]]
    return c == 0

def mask_pii_value(value: str, entity_type: str) -> str:
    if entity_type == "AADHAAR":
        clean = re.sub(r'\D', '', value)
        return f"XXXX-XXXX-{clean[-4:]}" if len(clean) >= 4 else "XXXX-XXXX-XXXX"
    elif entity_type == "PAN":
        return f"{value[:2]}XXXXX{value[-2:]}" if len(value) == 10 else "XXXXX1234X"
    elif entity_type == "EMAIL":
        parts = value.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[0] + "***" + name[-1] if len(name) > 2 else name[0] + "*"
            return f"{masked_name}@{domain}"
        return "x***@domain.com"
    elif entity_type == "PHONE_IN":
        clean = re.sub(r'\D', '', value)
        return f"+91-XXXXX-{clean[-4:]}" if len(clean) >= 4 else "+91-XXXXX-XXXXX"
    elif entity_type == "UPI":
        parts = value.split("@")
        return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "user***@upi"
    return value[:2] + "****" + value[-2:] if len(value) > 4 else "****"

class PIIRecognizer:
    def __init__(self):
        self.patterns = {
            "AADHAAR": re.compile(r'\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b'),
            "PAN": re.compile(r'\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b'),
            "UPI": re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@(ybl|okhdfcbank|okicici|okaxis|paytm|upi|sbi|ibl|postbank|barodampay)\b', re.IGNORECASE),
            "PHONE_IN": re.compile(r'(?:\+91[\-\s]?)?[6-9]\d{9}\b'),
            "IFSC": re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'),
            "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
            "IP_ADDRESS": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            "CREDIT_CARD": re.compile(r'\b(?:\d[ -]*?){13,16}\b')
        }

    def recognize(self, text: str, user_profile: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        detected = []
        seen_values = set()

        profile_email = user_profile.get("email", "").lower() if user_profile else ""
        profile_pan = user_profile.get("pan_masked", "").upper() if user_profile else ""
        profile_aadhaar_suffix = re.sub(r'\D', '', user_profile.get("aadhaar_masked", ""))[-4:] if user_profile else ""
        profile_upi = user_profile.get("upi_id", "").lower() if user_profile else ""

        for entity_type, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                val = match.group(0).strip()
                if val in seen_values:
                    continue

                is_valid = True
                if entity_type == "AADHAAR":
                    is_valid = verhoeff_validate(val)
                elif entity_type == "PHONE_IN" and len(re.sub(r'\D', '', val)) < 10:
                    is_valid = False

                if is_valid:
                    seen_values.add(val)
                    
                    # Cross-verify against monitored user profile
                    match_status = "UNAUTHORIZED_THIRD_PARTY_PII"
                    val_upper = val.upper()
                    val_lower = val.lower()
                    clean_digits = re.sub(r'\D', '', val)

                    if entity_type == "EMAIL" and val_lower == profile_email:
                        match_status = "MATCHED_USER_IDENTITY"
                    elif entity_type == "PAN" and val_upper == profile_pan:
                        match_status = "MATCHED_USER_IDENTITY"
                    elif entity_type == "UPI" and val_lower == profile_upi:
                        match_status = "MATCHED_USER_IDENTITY"
                    elif entity_type == "AADHAAR" and profile_aadhaar_suffix and clean_digits.endswith(profile_aadhaar_suffix):
                        match_status = "MATCHED_USER_IDENTITY"

                    detected.append({
                        "entity_type": entity_type,
                        "raw_value": val,
                        "masked_value": mask_pii_value(val, entity_type),
                        "identity_match_status": match_status,
                        "match_description": "Verified User Identity Token" if match_status == "MATCHED_USER_IDENTITY" else "Warning: Unrecognized Third-Party / Mismatched Identity PII",
                        "start": match.start(),
                        "end": match.end(),
                        "confidence": 0.98 if entity_type in ["AADHAAR", "PAN", "EMAIL"] else 0.90
                    })
        return detected
