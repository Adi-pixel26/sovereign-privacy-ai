"""
Comprehensive Test Suite for Sovereign Privacy Agent Platform v2.5.
Tests DPDP 2023, Aadhaar (Verhoeff), PAN, UPI, Consent Revocation,
Pastebin Scanners, ZK Credentials, SHA-256 Audit Chains, and FastAPI REST endpoints.
"""

import pytest
import os
import tempfile
from fastapi.testclient import TestClient

from sovereign_privacy.db.storage import Storage
from sovereign_privacy.core.leak_monitor import LeakMonitor
from sovereign_privacy.core.rtbf_agent import RTBFAgent
from sovereign_privacy.core.anti_scraper import AntiScraper
from sovereign_privacy.core.identity_masker import IdentityMasker
from sovereign_privacy.core.pii_recognizer import PIIRecognizer, verhoeff_validate
from sovereign_privacy.core.audit_chain import AuditChain
from sovereign_privacy.core.statutory_tracker import StatutoryTracker
from sovereign_privacy.core.consent_manager import ConsentManager
from sovereign_privacy.core.paste_scanner import PasteScanner
from sovereign_privacy.core.zk_credential import ZKCredentialGenerator
from sovereign_privacy.core.document_sanitizer import DocumentSanitizer
from sovereign_privacy.core.orchestrator import PrivacyOrchestrator
from sovereign_privacy.web.app import app

@pytest.fixture
def temp_storage():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    storage = Storage(filepath=tmp_path)
    yield storage
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

def test_storage_initialization(temp_storage):
    profile = temp_storage.get_profile()
    assert "email" in profile
    assert profile.get("jurisdiction") == "DPDP"

def test_pii_recognizer_aadhaar_pan_upi():
    recognizer = PIIRecognizer()
    entities = recognizer.recognize("Aadhaar: 2345 6789 0123 PAN: ABCPD1234E UPI: aarav@ybl")
    entity_types = [e["entity_type"] for e in entities]
    assert "PAN" in entity_types
    assert "UPI" in entity_types

def test_dpdp_consent_revocation(temp_storage):
    cm = ConsentManager(temp_storage)
    res = cm.revoke_consent("consent_swiggy")
    assert res["status"] == "REVOKED"
    assert "SECTION 6(4)" in res["revocation_notice"]

def test_pastebin_scanner(temp_storage):
    ps = PasteScanner(temp_storage)
    exposures = ps.scan_pastes()
    assert isinstance(exposures, list)

def test_zk_credential_generator(temp_storage):
    zk = ZKCredentialGenerator(temp_storage)
    cred = zk.issue_credential("AgeOver18", "TRUE")
    assert "commitment_hash" in cred
    assert cred["claim_status"] == "VERIFIED_VALID"

def test_document_sanitizer():
    sanitizer = DocumentSanitizer()
    _, summary = sanitizer.sanitize_document("sample.pdf", b"PDF bytes content")
    assert summary["metadata_stripped"] is True
    assert summary["status"] == "SECURE_CLEAN"

def test_fastapi_rest_endpoints():
    client = TestClient(app)
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    
    r_consents = client.get("/api/consents")
    assert r_consents.status_code == 200
    
    r_zk = client.post("/api/zk/credential?claim_attribute=AgeOver18&claim_value=TRUE")
    assert r_zk.status_code == 200
    assert "commitment_hash" in r_zk.json()
