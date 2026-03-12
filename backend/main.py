from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scanner import run_zap_scan, run_nikto_scan
from risk_engine import calculate_risk_score
from database import init_db, save_scan_result

app = FastAPI(title="OJS Security Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/")
def root():
    return {"status": "OJS Security Scanner is running"}

@app.post("/scan/zap")
def scan_zap():
    """Trigger ZAP scan terhadap OJS"""
    result = run_zap_scan()
    score = calculate_risk_score(result)
    save_scan_result("zap", result, score)
    return {"tool": "zap", "risk_score": score, "findings": result}

@app.post("/scan/nikto")
def scan_nikto():
    """Trigger Nikto scan terhadap OJS"""
    result = run_nikto_scan()
    score = calculate_risk_score(result)
    save_scan_result("nikto", result, score)
    return {"tool": "nikto", "risk_score": score, "findings": result}

@app.post("/scan/all")
def scan_all():
    """Trigger semua scanner sekaligus"""
    zap_result = run_zap_scan()
    nikto_result = run_nikto_scan()
    combined = zap_result + nikto_result
    score = calculate_risk_score(combined)
    save_scan_result("full", combined, score)
    return {"risk_score": score, "total_findings": len(combined), "findings": combined}

@app.get("/results")
def get_results():
    """Ambil semua hasil scan dari database"""
    from database import get_all_results
    return get_all_results()