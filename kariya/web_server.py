import os
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from kariya.pipeline import TriagePipeline
from kariya.evaluator import evaluate_pipeline
from kariya.offline_store import OfflineIncidentStore

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_PATH = os.path.join(os.path.dirname(__file__), "dataset.json")
TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "index.html")

app = FastAPI(title="KARIYA AI — Cyber Incident Triage Platform", version="2.0.0")

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

class TriageRequest(BaseModel):
    raw_text: str

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

@app.post("/api/toggle-offline")
async def toggle_offline():
    """Toggle offline resilience mode (Rule 06)."""
    current = offline_store.is_offline_mode()
    new_val = not current
    offline_store.set_offline_mode(new_val)
    if not new_val:
        # Reconnected: sync queued records
        synced = offline_store.sync_offline_queue()
        return {"offline_mode": False, "synced_count": synced, "message": f"Network restored. Synced {synced} queued reports."}
    return {"offline_mode": True, "message": "Network/Power cut simulated. System operating from local SQLite buffer."}

@app.get("/api/offline-status")
async def offline_status():
    """Check offline status and queue count."""
    return offline_store.get_stats()

def run_server(host: str = "0.0.0.0", port: int = None):
    import uvicorn
    if port is None:
        port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    run_server()
