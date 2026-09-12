"""
FastAPI Web Application & REST API Server for Sovereign Privacy Platform.
Supports India DPDP Act 2023, GDPR, CCPA, PII Recognizer (Aadhaar/PAN/UPI),
Cryptographic Audit Chains, and Interactive Dashboard.
"""

import os
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from sovereign_privacy.db.storage import Storage
from sovereign_privacy.core.orchestrator import PrivacyOrchestrator
from sovereign_privacy.core.pii_recognizer import PIIRecognizer
from sovereign_privacy.core.statutory_tracker import StatutoryTracker
from sovereign_privacy.core.consent_manager import ConsentManager
from sovereign_privacy.core.paste_scanner import PasteScanner
from sovereign_privacy.core.zk_credential import ZKCredentialGenerator
from sovereign_privacy.core.document_sanitizer import DocumentSanitizer

app = FastAPI(
    title="SovereignGuard AI — India & Global Sovereign Personal Privacy Protection",
    description="Proactive personal privacy agent for DPDP 2023, GDPR, CCPA, Aadhaar/PAN/UPI PII scanner, and anti-scraping honeytokens.",
    version="2.0.0"
)

storage = Storage()
orchestrator = PrivacyOrchestrator(storage)
pii_recognizer = PIIRecognizer()
statutory_tracker = StatutoryTracker(storage)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# --- Pydantic Request Models ---
class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    secondary_emails: Optional[List[str]] = None
    phone: Optional[str] = None
    aadhaar_masked: Optional[str] = None
    pan_masked: Optional[str] = None
    upi_id: Optional[str] = None
    jurisdiction: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    autoremoval_enabled: Optional[bool] = None

class CreateRTBFRequest(BaseModel):
    target_entity: str
    target_contact: str
    jurisdiction: Optional[str] = "DPDP"
    custom_notes: Optional[str] = ""

class CreateHoneytokenRequest(BaseModel):
    token_type: Optional[str] = "HONEY_URL"
    label: Optional[str] = "Web Beacon"
    target_placement: Optional[str] = "Footer HTML"

class CreateAliasRequest(BaseModel):
    service_name: str
    notes: Optional[str] = ""

class ZKProofRequest(BaseModel):
    attribute_name: str
    attribute_value: str

class TextScanRequest(BaseModel):
    text: str

# --- Web UI Routes ---
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# --- REST API Endpoints ---
@app.get("/api/health")
async def get_health():
    profile = storage.get_profile()
    leaks = storage.get_leaks()
    score, rating = orchestrator.leak_monitor.calculate_privacy_health(leaks)
    return {
        "status": "ONLINE",
        "agent": "SovereignGuard AI v2.0-DPDP",
        "privacy_health_score": score,
        "rating": rating,
        "monitored_target": profile.get("email"),
        "primary_jurisdiction": profile.get("jurisdiction", "DPDP")
    }

@app.get("/api/profile")
async def get_profile():
    return storage.get_profile()

@app.post("/api/profile")
async def update_profile(req: ProfileUpdateRequest):
    updates = req.model_dump(exclude_unset=True)
    return storage.update_profile(updates)

@app.get("/api/leaks")
async def get_leaks():
    leaks = storage.get_leaks()
    score, rating = orchestrator.leak_monitor.calculate_privacy_health(leaks)
    return {
        "privacy_health_score": score,
        "rating": rating,
        "total_leaks": len(leaks),
        "unresolved_leaks": len([l for l in leaks if l.get("status") == "UNRESOLVED"]),
        "leaks": leaks
    }

@app.post("/api/leaks/scan")
async def trigger_leak_scan():
    return orchestrator.leak_monitor.run_full_scan()

@app.post("/api/leaks/resolve/{leak_id}")
async def resolve_leak(leak_id: str):
    res = storage.update_leak_status(leak_id, "RESOLVED")
    if not res:
        raise HTTPException(status_code=404, detail="Leak not found")
    return storage.get_leaks()

@app.post("/api/leaks/resolve-all")
async def resolve_all_leaks():
    leaks = storage.get_leaks()
    for leak in leaks:
        storage.update_leak_status(leak["id"], "RESOLVED")
    return storage.get_leaks()

@app.post("/api/pii/scan-text")
async def scan_text_pii(req: TextScanRequest):
    """
    Scans input text and detects Aadhaar numbers, PAN cards, UPI IDs, Indian Mobile numbers, emails.
    Cross-verifies whether PII belongs to monitored user or an unrecognized third party.
    """
    user_profile = storage.get_profile()
    entities = pii_recognizer.recognize(req.text, user_profile=user_profile)
    return {
        "detected_count": len(entities),
        "entities": entities
    }

@app.get("/api/brokers")
async def get_brokers():
    return storage.get_brokers()

@app.get("/api/rtbf")
async def get_rtbf_requests():
    reqs = storage.get_rtbf_requests()
    # Attach statutory timeline to each request
    for r in reqs:
        r["statutory_timeline"] = statutory_tracker.calculate_deadline(
            r.get("created_at", ""),
            r.get("jurisdiction", "DPDP")
        )
        r["milestones"] = statutory_tracker.generate_milestones(
            r.get("jurisdiction", "DPDP"),
            r.get("status", "DRAFT")
        )
    return reqs

@app.post("/api/rtbf/create")
async def create_rtbf(req: CreateRTBFRequest):
    return orchestrator.rtbf_agent.create_request(
        target_entity=req.target_entity,
        target_contact=req.target_contact,
        jurisdiction=req.jurisdiction or "DPDP",
        custom_notes=req.custom_notes or ""
    )

@app.post("/api/rtbf/auto-broker/{broker_id}")
async def auto_broker_rtbf(broker_id: str):
    res = orchestrator.rtbf_agent.auto_generate_for_broker(broker_id)
    if not res:
        raise HTTPException(status_code=404, detail="Broker not found")
    return res

@app.post("/api/rtbf/dispatch/{request_id}")
async def dispatch_rtbf(request_id: str):
    res = orchestrator.rtbf_agent.dispatch_request(request_id)
    if not res:
        raise HTTPException(status_code=404, detail="RTBF request not found")
    return res

@app.post("/api/rtbf/batch-dispatch")
async def batch_dispatch_rtbf():
    return orchestrator.rtbf_agent.batch_dispatch_all_drafts()

@app.get("/api/canary")
async def get_honeytokens():
    return storage.get_honeytokens()

@app.post("/api/canary/create")
async def create_honeytoken(req: CreateHoneytokenRequest):
    return orchestrator.anti_scraper.create_honeytoken(
        token_type=req.token_type or "HONEY_URL",
        label=req.label or "Web Beacon",
        target_placement=req.target_placement or "HTML Embed"
    )

@app.get("/api/canary/beacon/{key}")
async def trigger_canary_beacon(key: str, request: Request):
    client_ip = request.client.host if request.client else "Unknown"
    user_agent = request.headers.get("user-agent", "Unknown Scraper")
    storage.trigger_honeytoken(token_key=key, scraper_ip=client_ip, user_agent=user_agent)
    return JSONResponse(content={"alert": "HONEYTOKEN_TRIGGERED", "token_key": key, "scraper_ip": client_ip})

@app.get("/api/anti-scraper/robots", response_class=PlainTextResponse)
async def get_robots_txt():
    return orchestrator.anti_scraper.generate_anti_scraping_robots_txt()

@app.get("/api/anti-scraper/headers")
async def get_security_headers():
    return orchestrator.anti_scraper.generate_anti_scraping_headers()

@app.get("/api/aliases")
async def get_aliases():
    return storage.get_aliases()

@app.post("/api/aliases/create")
async def create_alias(req: CreateAliasRequest):
    return orchestrator.identity_masker.generate_email_alias(
        service_name=req.service_name,
        notes=req.notes or ""
    )

@app.post("/api/aliases/synthetic")
async def create_synthetic_profile(service_name: str = Form(...)):
    return orchestrator.identity_masker.generate_synthetic_profile(service_name)

@app.post("/api/aliases/zk-proof")
async def create_zk_proof(req: ZKProofRequest):
    return orchestrator.identity_masker.generate_zk_attribute_proof(
        attribute_name=req.attribute_name,
        attribute_value=req.attribute_value
    )

@app.post("/api/sanitizer/image")
async def sanitize_image(file: UploadFile = File(...)):
    contents = await file.read()
    _, summary = orchestrator.anti_scraper.sanitize_image_metadata(file.filename, contents)
    return summary

@app.get("/api/audit/verify")
async def verify_audit_chain():
    return storage.audit_chain.verify_chain()

@app.get("/api/consents")
async def get_consents():
    cm = ConsentManager(storage)
    return cm.get_consents()

@app.post("/api/consents/revoke/{consent_id}")
async def revoke_consent(consent_id: str):
    cm = ConsentManager(storage)
    return cm.revoke_consent(consent_id)

@app.get("/api/pastes/scan")
async def scan_pastes():
    ps = PasteScanner(storage)
    return ps.scan_pastes()

@app.post("/api/zk/credential")
async def issue_zk_credential(claim_attribute: str = "AgeOver18", claim_value: str = "TRUE"):
    zk = ZKCredentialGenerator(storage)
    return zk.issue_credential(claim_attribute, claim_value)

@app.post("/api/sanitizer/document")
async def sanitize_doc(file: UploadFile = File(...)):
    contents = await file.read()
    _, summary = DocumentSanitizer.sanitize_document(file.filename, contents)
    return summary

from sovereign_privacy.core.agentic_ai import AgenticAIAgent

@app.post("/api/agentic-ai/run")
async def run_agentic_ai():
    agentic_ai = AgenticAIAgent(storage)
    return await agentic_ai.execute_autonomous_web_agent_loop()

@app.post("/api/agent/run-cycle")
async def run_agent_cycle():
    return orchestrator.execute_autonomous_defense_cycle()

@app.get("/api/agent/logs")
async def get_agent_logs(limit: int = 50):
    return storage.get_agent_logs(limit=limit)
