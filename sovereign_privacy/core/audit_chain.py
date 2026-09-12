"""
Cryptographic Audit Trail (SHA-256 Block-Linked Receipts).
Generates immutable, verifiable cryptographic proofs for legal notices,
takedown actions, and data broker opt-out dispatches under DPDP/GDPR/CCPA.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

class AuditReceipt:
    def __init__(self, index: int, action: str, data: Dict[str, Any], previous_hash: str):
        self.index = index
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.action = action
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "action": self.action,
            "data": self.data,
            "previous_hash": self.previous_hash
        }
        raw = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "action": self.action,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class AuditChain:
    def __init__(self):
        self.chain: List[Dict[str, Any]] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = AuditReceipt(
            index=0,
            action="GENESIS_BLOCK",
            data={"system": "SovereignGuard AI Audit Engine", "version": "2.0.0-INDIA-DPDP"},
            previous_hash="0" * 64
        )
        self.chain.append(genesis.to_dict())

    def add_receipt(self, action: str, data: Dict[str, Any]) -> Dict[str, Any]:
        last_block = self.chain[-1]
        new_receipt = AuditReceipt(
            index=len(self.chain),
            action=action,
            data=data,
            previous_hash=last_block["hash"]
        )
        dict_receipt = new_receipt.to_dict()
        self.chain.append(dict_receipt)
        return dict_receipt

    def verify_chain(self) -> Dict[str, Any]:
        """Verifies the cryptographic integrity of the entire audit chain."""
        breaks = []
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]

            if curr["previous_hash"] != prev["hash"]:
                breaks.append(f"Chain broken at index {i}: previous_hash mismatch.")

            # Recompute hash
            payload = {
                "index": curr["index"],
                "timestamp": curr["timestamp"],
                "action": curr["action"],
                "data": curr["data"],
                "previous_hash": curr["previous_hash"]
            }
            recomputed = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
            if recomputed != curr["hash"]:
                breaks.append(f"Chain tampered at index {i}: hash mismatch.")

        return {
            "chain_valid": len(breaks) == 0,
            "total_blocks": len(self.chain),
            "breaks": breaks
        }
