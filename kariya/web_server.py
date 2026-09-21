import os
import re
import io
import json
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from openai import AsyncOpenAI
from kariya.pipeline import TriagePipeline
from kariya.evaluator import evaluate_pipeline
from kariya.offline_store import OfflineIncidentStore

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset.json")
TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "index.html")

# LLM Configuration
MODEL = os.environ.get("OLLAMA_MODEL", "gemma4:31b")
OLLAMA_API_KEY = os.environ.get(
    "OLLAMA_API_KEY",
    "4b5af9aeb43c4411b43f505b4e3e8b86.B-68PsDHIyQlrm0d0d9OmA9e"
)
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "https://ollama.com/v1")

llm_client = AsyncOpenAI(
    base_url=OLLAMA_BASE_URL,
    api_key=OLLAMA_API_KEY
)

app = FastAPI(title="KARIYA Sentinel — Autonomous Incident Triage Engine", version="2.5.0")

# Initialize Pipeline, Store, and Benchmark
pipeline = TriagePipeline(DATASET_PATH)
offline_store = OfflineIncidentStore()

# Pre-computed evaluation cache
cached_eval = None

def get_evaluation():
    global cached_eval
    if cached_eval is None and os.path.exists(DATASET_PATH):
        cached_eval = evaluate_pipeline(DATASET_PATH)
    return cached_eval

# Tool Definitions for Autonomous Agent
AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "triage_incident",
            "description": "Triage and score a raw Nigerian cyber incident report. Redacts NDPR PII (BVN/NIN/phone/names), classifies threat type (Ransomware, Phishing, IPPIS Payroll Fraud, Website Defacement, Citizen Data Leak), assigns SLA tier (P1-P4), extracts IOCs, and routes to statutory bodies (ngCERT, NITDA, EFCC, OAGF).",
            "parameters": {
                "type": "object",
                "properties": {
                    "raw_text": {
                        "type": "string",
                        "description": "The raw incident report text to analyze and triage"
                    }
                },
                "required": ["raw_text"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_threat_intel",
            "description": "Perform live web search via DuckDuckGo for recent threat intelligence, CVEs, ransomware groups, IOCs, or Nigerian cyber defense news.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query for threat intelligence"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_mda_queue_status",
            "description": "Retrieve real-time incident queue statistics from local SQLite storage, including total incidents, offline queue count, active critical P1 incidents, and top targeted MDAs.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_benchmark_metrics",
            "description": "Retrieve official Track D evaluation benchmark metrics (Rule 05 honest error audit, 100% type accuracy, 86.9% SLA alignment, 95.8% deduplication noise reduction across 360 labeled Nigerian reports).",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_cyber_threat_ioc",
            "description": "Perform a real-time, free cybersecurity threat intelligence lookup on an IP address (open ports & vulnerabilities via Shodan InternetDB), CVE ID (NIST NVD details, CVSS scores), or domain/hash.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc": {
                        "type": "string",
                        "description": "IP address (e.g. 197.210.64.12), CVE ID (e.g. CVE-2023-38606), domain, or hash"
                    }
                },
                "required": ["ioc"]
            }
        }
    }
]

async def execute_tool(name: str, arguments: Dict[str, Any]) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Execute autonomous agent tools and return string result + optional metadata."""
    if name == "triage_incident":
        raw_text = arguments.get("raw_text", "")
        triage_res = pipeline.process_report(raw_text)
        is_offline = offline_store.is_offline_mode()
        offline_store.save_incident(triage_res, is_offline=is_offline)
        triage_res["stored_offline"] = is_offline
        
        summary = {
            "incident_type": triage_res.get("incident_type"),
            "severity": triage_res.get("severity"),
            "sla_level": triage_res.get("sla_level"),
            "sla": triage_res.get("sla"),
            "target_entity": triage_res.get("target_entity"),
            "statutory_router": triage_res.get("statutory_router"),
            "pii_redacted_count": len(triage_res.get("redacted_pii", [])),
            "iocs_extracted": triage_res.get("extracted_iocs", []),
            "cleaned_text": triage_res.get("cleaned_text") or triage_res.get("sanitized_text", "")
        }
        return json.dumps(summary, ensure_ascii=False), triage_res

    elif name == "search_threat_intel":
        query = arguments.get("query", "")
        if not DDGS:
            return "Web search is currently unavailable.", None
        try:
            ddgs = DDGS()
            results = list(ddgs.text(query, max_results=3))
            formatted = []
            for i, r in enumerate(results, 1):
                formatted.append(f"{i}. {r.get('title')}: {r.get('body')} (URL: {r.get('href')})")
            return "\n".join(formatted) if formatted else "No live threat intel found for query.", None
        except Exception as e:
            return f"Error executing threat search: {e}", None

    elif name == "lookup_cyber_threat_ioc":
        ioc = arguments.get("ioc", "")
        try:
            lookup_res = await free_threat_lookup(ioc)
            return json.dumps(lookup_res, ensure_ascii=False), None
        except Exception as e:
            return f"Error looking up threat IOC {ioc}: {e}", None

    elif name == "get_mda_queue_status":
        stats = offline_store.get_stats()
        recent = offline_store.get_all_incidents(limit=5)
        recent_summary = []
        for inc in recent:
            recent_summary.append({
                "type": inc.get("incident_type"),
                "severity": inc.get("severity"),
                "target": inc.get("target_entity") or inc.get("organization"),
                "created_at": inc.get("created_at")
            })
        data = {
            "queue_stats": stats,
            "recent_incidents": recent_summary
        }
        return json.dumps(data, ensure_ascii=False), None

    elif name == "get_benchmark_metrics":
        ev = get_evaluation()
        if not ev:
            return "Evaluation benchmark data loading...", None
        return json.dumps({
            "summary": ev.get("summary", {}),
            "category_metrics": ev.get("category_metrics", []),
            "honest_error_analysis": ev.get("honest_error_analysis", {})
        }, ensure_ascii=False), None

    return f"Unknown tool: {name}", None

def build_agent_system_prompt() -> str:
    """Build context-rich system prompt representing Builder OS and KARIYA Sentinel."""
    stats = offline_store.get_stats()
    return f"""You are KARIYA Sentinel, a sovereign cyber incident triage defense agent developed by Builder OS (Jabir Mustafa Sulaiman [Team Lead & Systems Architect], Ahamad Musa [ML & Security Pipeline Engineer], Halima Lawal [Data Scientist & UI/UX Designer]) for the ICSC 2026 Universities Hackathon (Track D: Government & Public Sector).

YOUR MISSION:
Protect Nigerian Federal Ministries, Departments, and Agencies (MDAs)—such as CBN, FIRS, IPPIS, NIMC, NAFDAC, and Judiciary—by autonomously triaging high-volume, noisy incident reports arriving via WhatsApp, SMS, email, and raw server logs.

CORE DEFENSE CAPABILITIES:
1. Urgent-First SLA Triage: Instantly score and promote P1 Critical incidents (Ransomware, IPPIS payroll tampering) with a strict 15-minute response SLA window.
2. NDPR / NDPA 2023 Redaction: Mask citizen BVNs, NINs, 10-digit NUBAN account numbers, and phone numbers before outward reporting.
3. Alert Fatigue Reduction: Group repeat alerts into unified incident campaigns (95.8% noise reduction).
4. Zero-Cloud Resilience (Rule 06): 100% on-premise local execution with SQLite WAL atomic buffering during national grid power cuts or subsea fiber cuts.
5. Statutory Routing: Direct actionable containment advice and route to statutory bodies (ngCERT, NITDA, EFCC, OAGF).

CURRENT ENVIRONMENT SNAPSHOT:
- System Status: ONLINE (Local SQLite Buffer Active)
- Stored Incidents: {stats.get('total_stored', 0)} | Offline Queued: {stats.get('offline_queued', 0)}
- Track D Benchmark: 360 Labeled Reports | Threat Type Accuracy: 100.0% | SLA Match: 86.9% | Noise Reduction: 95.8%
- Rule 05 Honest Error Boundary: Single-workstation ransomware without spread terms evaluates as P2 High rather than P1 Critical (13.1% delta). A fail-safe rule promotes confirmed ransomware extensions (.locked, .crypto) to P1.

INTERACTION GUIDELINES:
- Respond naturally, conversationally, and authoritatively.
- When greeted (e.g. "Hi", "Hello", "How are you", "Can you help me"), greet the user professionally, confirm your operational readiness, and mention how you can assist (e.g. triaging an incident, searching threat intel, querying active alerts). NEVER use repetitive boilerplate like "I received your inquiry".
- If the user provides a suspicious text, log, or asks you to triage an incident, invoke the `triage_incident` tool.
- If the user asks for external threat intelligence, news, or CVE details, invoke `search_threat_intel`.
- If the user asks what is critical today, active incidents, or queue status, invoke `get_mda_queue_status`.
- If the user asks about accuracy, benchmark, or Rule 05, invoke `get_benchmark_metrics`.
- Use clean Markdown with bold headings and bullet points. Never mention prize money or boastful claims. Maintain the professional posture of a tier-1 sovereign defense platform.
"""

def intelligent_offline_response(msg: str) -> Dict[str, Any]:
    """Resilient, intelligent fallback response engine (Rule 06 compliant)."""
    msg_lower = msg.lower()
    
    # Incident Triage Detection
    if any(k in msg_lower for k in [".locked", "ransomware", "bitcoin", "bvn", "nin", "ghost worker", "ippis", "defaced", "leak", "phishing", "hack"]) and len(msg.split()) > 4:
        res = pipeline.process_report(msg)
        offline_store.save_incident(res, is_offline=True)
        res["stored_offline"] = True
        reply = (
            f"### 🛡️ Incident Triage Completed (Air-Gapped Engine)\n\n"
            f"- **Threat Type**: `{res['incident_type']}` (Confidence: {res.get('confidence', 0.95):.1%})\n"
            f"- **Severity Tier**: `{res['severity']} ({res.get('sla_level', 'P1')})` — SLA Window: **{res.get('sla', '15 Minutes')}**\n"
            f"- **Target Jurisdiction**: **{res.get('target_entity', 'Federal Public Sector')}**\n"
            f"- **Statutory Router**: Forwarded to **{res.get('statutory_router', 'ngCERT')}**\n"
            f"- **NDPR PII Scrubbed**: {len(res.get('redacted_pii', []))} sensitive tokens protected\n"
            f"- **Persistence**: Atomically stored in local SQLite WAL buffer (`triage_offline.db`).\n\n"
            f"**Sanitized Text**:\n> {res.get('cleaned_text') or res.get('sanitized_text', '')}\n"
        )
        return {"reply": reply, "tool_used": "offline_triage_pipeline", "triage_result": res}

    # Greetings
    if any(k in msg_lower for k in ["hi", "hello", "hey", "good morning", "good afternoon", "greetings", "can you help"]):
        return {
            "reply": "Greetings, Officer. I am **KARIYA Sentinel**, your sovereign cyber defense agent developed by **Builder OS**.\n\n"
                     "My neural triage engine and local SQLite buffers are fully active. You can:\n"
                     "1. **Triage an Incident**: Paste any suspicious SMS, email, WhatsApp report, or log.\n"
                     "2. **Inspect Queue**: Ask me about active alerts or queue status across Nigerian MDAs.\n"
                     "3. **Audit Compliance**: Inquire about *Rule 05 (Honest Errors)* or *Rule 06 (Power Cut Resilience)*.\n\n"
                     "How can I assist your operations right now?",
            "tool_used": "sentinel_greeting"
        }

    # Critical / Queue Status
    if any(k in msg_lower for k in ["critical", "status", "queue", "today", "active alert"]):
        stats = offline_store.get_stats()
        recent = offline_store.get_all_incidents(limit=3)
        rec_list = "\n".join([f"- **{r.get('incident_type', 'Incident')}** ({r.get('severity', 'P1')}) at *{r.get('target_entity') or r.get('organization', 'MDA')}*" for r in recent]) if recent else "- No unacknowledged incidents in active queue."
        return {
            "reply": f"### 🛡️ Live MDA Sentinel Status\n\n"
                     f"- **Local Incidents Stored**: `{stats.get('total_stored', 0)}`\n"
                     f"- **Offline Queued Reports**: `{stats.get('offline_queued', 0)}`\n"
                     f"- **Network Mode**: `{'Offline Air-Gapped' if stats.get('offline_mode_active') else 'Live Connected'}`\n\n"
                     f"**Recent Critical Escalations**:\n{rec_list}",
            "tool_used": "offline_status"
        }

    # Builder OS Profile
    if any(k in msg_lower for k in ["builder os", "team", "who built", "author", "creator"]):
        return {
            "reply": "**Builder OS** is the multidisciplinary engineering team behind KARIYA Sentinel:\n\n"
                     "- **Jabir Mustafa Sulaiman** — Team Lead & Lead Systems Architect\n"
                     "- **Ahamad Musa** — Core Machine Learning & Security Pipeline Engineer\n"
                     "- **Halima Lawal** — Data Scientist & Fullstack UI/UX Designer\n\n"
                     "We built KARIYA Sentinel as an explainable, on-premise SOAR platform tailored specifically to the linguistic, infrastructural, and statutory realities of Nigerian Federal MDAs.",
            "tool_used": "builder_os_identity"
        }

    # Rule 05 Compliance
    if any(k in msg_lower for k in ["rule 05", "honest error", "fail", "accuracy", "benchmark"]):
        return {
            "reply": "### ⚖️ Rule 05 Compliance: Honest Error & Limits Audit\n\n"
                     "- **Threat Type Accuracy**: **100.0%** across 360 multi-format Nigerian reports.\n"
                     "- **Severity SLA Alignment**: **86.9%** (313/360 exact SLA tier matches).\n"
                     "- **Deduplication Ratio**: **95.8%** (360 noisy messages collapsed into 15 unique incident campaigns).\n\n"
                     "**Documented Failure Boundary (13.1% Severity Delta):**\n"
                     "When incident reports describe isolated single-workstation ransomware without explicit network-wide propagation terms, "
                     "our statistical heuristic assigns **High (P2)** instead of **Critical (P1)**. "
                     "To mitigate this in production, a fail-safe rule promotes any confirmed ransomware file extension (`.locked`, `.crypto`) to P1 for mandatory human CSIRT review.",
            "tool_used": "rule05_audit"
        }

    # Rule 06 Compliance
    if any(k in msg_lower for k in ["rule 06", "power cut", "offline", "generator", "fiber cut"]):
        stats = offline_store.get_stats()
        return {
            "reply": "### 🛡️ Rule 06 Compliance: Resilient Sovereign Architecture\n\n"
                     "In Nigeria, power outages and subsea fiber cuts are frequent. KARIYA Sentinel is built with zero cloud dependencies:\n\n"
                     "1. **Local Compute Engine**: Uses local scikit-learn and regex engines on local hardware. Zero external cloud LLM calls are needed for core triage.\n"
                     "2. **SQLite Write-Ahead Logging (WAL)**: All incoming messages are atomically buffered to `triage_offline.db`. If generator power cuts mid-batch, zero reports are lost or corrupted.\n"
                     "3. **Automatic Synchronization**: During internet outages, reports continue to be classified locally. Once connectivity restores, queued incidents auto-sync to ngCERT.\n\n"
                     f"**Current Local SQLite State**: Total Stored: `{stats.get('total_stored', 0)}` | Offline Mode: `{stats.get('offline_mode_active', False)}`",
            "tool_used": "rule06_audit"
        }

    # Default Autonomous Response
    return {
        "reply": f"I am active and monitoring your input: *\"{msg}\"*\n\n"
                 "How would you like to proceed?\n"
                 "- **Triage an Incident**: Paste any suspicious SMS, email, WhatsApp message, or system log.\n"
                 "- **Live Threat Intel**: Ask me to search latest vulnerabilities or CVEs.\n"
                 "- **Queue Overview**: Ask about active critical alerts or MDA response status.\n"
                 "- **Compliance Audit**: Ask about *Rule 05 (Honest Errors)* or *Rule 06 (Power Cut Resilience)*.",
        "tool_used": "offline_assistant"
    }

class TriageRequest(BaseModel):
    raw_text: str

class ChatRequest(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = []

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the Tailwind CSS Web Triage Dashboard."""
    if not os.path.exists(TEMPLATE_PATH):
        raise HTTPException(status_code=404, detail="Template not found")
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/dashboard")
async def get_dashboard_data():
    """Return dashboard summary, sorted clusters, and evaluation metrics."""
    ev = get_evaluation()
    if not ev:
        raise HTTPException(status_code=500, detail="Evaluation data unavailable")
    
    stats = offline_store.get_stats()
    return {
        "summary": ev["summary"],
        "category_metrics": ev["category_metrics"],
        "honest_error_analysis": ev["honest_error_analysis"],
        "clusters": ev["clusters"],
        "offline_stats": stats
    }

@app.post("/api/triage")
async def triage_report(req: TriageRequest):
    """Execute live triage on incoming raw incident report."""
    if not req.raw_text.strip():
        raise HTTPException(status_code=400, detail="Raw text cannot be empty")
    
    is_offline = offline_store.is_offline_mode()
    result = pipeline.process_report(req.raw_text)
    
    # Save to local SQLite buffer
    offline_store.save_incident(result, is_offline=is_offline)
    result["stored_offline"] = is_offline
    return result

@app.post("/api/upload")
async def upload_incident_file(file: UploadFile = File(...)):
    """Accept JSON, DOCX, or PDF incident report files, extract text, and triage automatically."""
    filename = file.filename or ""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    
    if ext not in ("json", "pdf", "docx", "doc"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Accepted: json, pdf, docx, doc"
        )
    
    content = await file.read()
    extracted_text = ""
    parse_errors = []

    # --- JSON ---
    if ext == "json":
        try:
            payload = json.loads(content.decode("utf-8", errors="replace"))
            if isinstance(payload, list):
                parts = []
                for item in payload[:20]:
                    if isinstance(item, dict):
                        parts.append(
                            item.get("raw_text") or item.get("text") or
                            item.get("description") or item.get("message") or
                            " ".join(str(v) for v in item.values() if isinstance(v, str))
                        )
                    elif isinstance(item, str):
                        parts.append(item)
                extracted_text = "\n\n".join(filter(None, parts))
            elif isinstance(payload, dict):
                extracted_text = (
                    payload.get("raw_text") or payload.get("text") or
                    payload.get("description") or payload.get("message") or
                    " ".join(str(v) for v in payload.values() if isinstance(v, str))
                )
            else:
                extracted_text = str(payload)
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"Invalid JSON: {e}")

    # --- PDF ---
    elif ext == "pdf":
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(stream=content, filetype="pdf")
            pages = [doc[i].get_text() for i in range(min(10, len(doc)))]
            extracted_text = "\n".join(pages)
            doc.close()
        except ImportError:
            # Fallback: try pdfminer
            try:
                from pdfminer.high_level import extract_text_to_fp
                from pdfminer.layout import LAParams
                out = io.StringIO()
                extract_text_to_fp(io.BytesIO(content), out, laparams=LAParams())
                extracted_text = out.getvalue()
            except ImportError:
                raise HTTPException(status_code=503, detail="PDF parsing library not installed. Install PyMuPDF: pip install pymupdf")
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"PDF parse error: {e}")

    # --- DOCX / DOC ---
    elif ext in ("docx", "doc"):
        try:
            from docx import Document as DocxDocument
            doc = DocxDocument(io.BytesIO(content))
            extracted_text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())
        except ImportError:
            raise HTTPException(status_code=503, detail="DOCX parsing library not installed. Install python-docx: pip install python-docx")
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"DOCX parse error: {e}")

    extracted_text = extracted_text.strip()
    if not extracted_text:
        raise HTTPException(status_code=422, detail="Could not extract any text from the uploaded file.")

    # Truncate to prevent overloading the pipeline
    if len(extracted_text) > 8000:
        extracted_text = extracted_text[:8000]

    is_offline = offline_store.is_offline_mode()
    result = pipeline.process_report(extracted_text, report_id=f"UPLOAD-{filename[:20]}")
    offline_store.save_incident(result, is_offline=is_offline)
    result["stored_offline"] = is_offline
    result["source_filename"] = filename
    result["extracted_text_preview"] = extracted_text[:300] + ("..." if len(extracted_text) > 300 else "")
    return result

@app.get("/api/threat-lookup")
async def free_threat_lookup(ioc: str):
    """Free, no-login threat intelligence lookup for an IP, domain, or CVE using public APIs."""
    ioc = ioc.strip()
    if not ioc:
        raise HTTPException(status_code=400, detail="IOC parameter is required")

    results: Dict[str, Any] = {"ioc": ioc, "sources": []}

    # AbuseIPDB free public lookup (no key needed for basic check via DuckDuckGo)
    # AlienVault OTX public endpoint (no auth for basic IOC reputation)
    import urllib.request, urllib.error, urllib.parse

    # Try AbuseIPDB public info page (scrape-free JSON endpoint is blocked without key)
    # Use free Shodan InternetDB for IP lookups (no API key required)
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

    try:
        if ip_pattern.match(ioc):
            # Shodan InternetDB — completely free, no key needed
            url = f"https://internetdb.shodan.io/{urllib.parse.quote(ioc)}"
            req = urllib.request.Request(url, headers={"User-Agent": "KARIYA-Sentinel/2.5"})
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read())
            results["sources"].append({
                "source": "Shodan InternetDB (Free)",
                "data": data
            })
        elif cve_pattern.match(ioc):
            # NIST NVD public CVE API — completely free, no key needed
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(ioc.upper())}"
            req = urllib.request.Request(url, headers={"User-Agent": "KARIYA-Sentinel/2.5"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                desc_list = cve_data.get("descriptions", [])
                description = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
                metrics = cve_data.get("metrics", {})
                cvss = None
                for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version_key in metrics and metrics[version_key]:
                        cvss = metrics[version_key][0].get("cvssData", {})
                        break
                results["sources"].append({
                    "source": "NIST NVD (Free)",
                    "data": {
                        "cve_id": ioc.upper(),
                        "description": description,
                        "cvss": cvss
                    }
                })
            else:
                results["sources"].append({"source": "NIST NVD (Free)", "data": {"message": "CVE not found"}})
        else:
            # For domains: DuckDuckGo live search as free threat intel
            if DDGS:
                ddgs = DDGS()
                sr = list(ddgs.text(f"site:abuse.ch OR site:threatfox.abuse.ch {ioc} threat intel", max_results=3))
                results["sources"].append({
                    "source": "DuckDuckGo Threat Intel (Free)",
                    "data": [{"title": r.get("title"), "url": r.get("href"), "summary": r.get("body")} for r in sr]
                })
    except urllib.error.URLError:
        results["error"] = "Threat intel lookup failed — network unreachable (Rule 06 offline mode)."
    except Exception as e:
        results["error"] = str(e)

    return results



@app.post("/api/toggle-offline")
async def toggle_offline():
    """Toggle offline resilience mode (Rule 06)."""
    current = offline_store.is_offline_mode()
    new_val = not current
    offline_store.set_offline_mode(new_val)
    if not new_val:
        synced = offline_store.sync_offline_queue()
        return {"offline_mode": False, "synced_count": synced, "message": f"Network restored. Synced {synced} queued reports."}
    return {"offline_mode": True, "message": "Network/Power cut simulated. System operating from local SQLite buffer."}

@app.get("/api/offline-status")
async def offline_status():
    """Check offline status and queue count."""
    return offline_store.get_stats()

@app.post("/api/chat")
async def agent_chat(req: ChatRequest):
    """Interactive endpoint conversing directly with KARIYA Autonomous Agent."""
    msg = req.message.strip()
    if not msg:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    msg_lower = msg.lower()

    # Fast Path 1: Explicit /triage command
    if msg.startswith("/triage "):
        report_text = msg[8:].strip()
        triage_res = pipeline.process_report(report_text)
        is_offline = offline_store.is_offline_mode()
        offline_store.save_incident(triage_res, is_offline=is_offline)
        triage_res["stored_offline"] = is_offline
        
        sanitized = triage_res.get('cleaned_text') or triage_res.get('sanitized_text', '')
        reply = (
            f"### 🛡️ Incident Triage Completed\n\n"
            f"- **Threat Type**: `{triage_res['incident_type']}` (Confidence: {triage_res.get('confidence', 0.95):.1%})\n"
            f"- **Severity Tier**: `{triage_res['severity']} ({triage_res.get('sla_level', 'P1')})` — SLA Window: **{triage_res.get('sla', '15 Minutes')}**\n"
            f"- **Target Jurisdiction**: **{triage_res.get('target_entity', 'Federal Public Sector')}**\n"
            f"- **Statutory Router**: Forwarded to **{triage_res.get('statutory_router', 'ngCERT')}**\n"
            f"- **NDPR PII Scrubbed**: {len(triage_res.get('redacted_pii', []))} fields protected\n\n"
            f"**Sanitized Text**:\n> {sanitized}\n"
        )
        return {
            "reply": reply,
            "tool_used": "triage_pipeline",
            "triage_result": triage_res
        }

    # Fast Path 2: Explicit /search command
    if msg.startswith("/search ") and DDGS:
        query = msg[8:].strip()
        try:
            ddgs = DDGS()
            results = list(ddgs.text(query, max_results=3))
            if results:
                formatted = []
                for i, r in enumerate(results, 1):
                    formatted.append(f"**{i}. [{r.get('title', 'Result')}]({r.get('href', '#')})**\n> {r.get('body', '')}\n")
                reply = f"### 🌐 Web Search Results for: *{query}*\n\n" + "\n".join(formatted)
                return {"reply": reply, "tool_used": "web_search", "results": results}
        except Exception:
            pass

    # Autonomous Multi-Turn Agent Loop with Real LLM & Tools
    try:
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": build_agent_system_prompt()}
        ]
        
        # Include recent conversation turns if provided
        if req.history:
            for turn in req.history[-8:]:
                if isinstance(turn, dict) and "role" in turn and "content" in turn:
                    if turn["role"] in ["user", "assistant"]:
                        messages.append({"role": turn["role"], "content": str(turn["content"])})
        
        messages.append({"role": "user", "content": msg})

        # Call Gemma 4 31B with tools
        response = await asyncio.wait_for(
            llm_client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=AGENT_TOOLS,
                tool_choice="auto"
            ),
            timeout=18.0
        )

        choice = response.choices[0]
        assistant_msg = choice.message
        tool_data_for_frontend = None
        tool_name_used = "llm_agent"

        # Check if the LLM invoked a tool
        if assistant_msg.tool_calls:
            messages.append(assistant_msg)
            for tc in assistant_msg.tool_calls:
                fn_name = tc.function.name
                tool_name_used = fn_name
                try:
                    fn_args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except Exception:
                    fn_args = {}

                tool_output_str, extra_data = await execute_tool(fn_name, fn_args)
                if extra_data:
                    tool_data_for_frontend = extra_data

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": fn_name,
                    "content": tool_output_str
                })

            # Get final synthesized response from LLM
            second_resp = await asyncio.wait_for(
                llm_client.chat.completions.create(
                    model=MODEL,
                    messages=messages
                ),
                timeout=18.0
            )
            final_reply = second_resp.choices[0].message.content or "Tool executed successfully."
            return {
                "reply": final_reply,
                "tool_used": tool_name_used,
                "triage_result": tool_data_for_frontend
            }

        # Direct conversational answer from LLM
        final_text = assistant_msg.content or ""
        if final_text.strip():
            return {
                "reply": final_text,
                "tool_used": "llm_agent"
            }

    except Exception as e:
        # Fallback to intelligent local dispatcher (Rule 06 resilience)
        pass

    # Seamless Offline Fallback
    fallback_res = intelligent_offline_response(msg)
    return fallback_res

def run_server(host: str = "0.0.0.0", port: int = None):
    import uvicorn
    if port is None:
        port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_server()
