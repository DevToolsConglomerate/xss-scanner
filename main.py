from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from contextlib import asynccontextmanager
import os
import stripe
import logging

# --- Configuration ---
MONGODB_URI = os.getenv("MONGODB_URI")
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
stripe.api_key = STRIPE_API_KEY

# --- Lifespan Events ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Connect to DB
    app.mongodb_client = MongoClient(MONGODB_URI)
    app.database = app.mongodb_client.get_database("devtools_conglomerate")
    logging.info("Connected to MongoDB")
    yield
    # Shutdown: Close DB connection
    app.mongodb_client.close()
    logging.info("Disconnected from MongoDB")

# --- FastAPI App Initialization ---
app = FastAPI(lifespan=lifespan, title="XSS Scanner API", version="1.0.0")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Dependency: Get API Key from Header ---
async def get_api_key(x_api_key: str = Header(None)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API Key")
    # Check if key exists and is active in MongoDB
    key_doc = app.database.api_keys.find_one({"key": x_api_key, "is_active": True})
    if not key_doc:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return key_doc

# --- Generic Health Check Endpoint (for all APIs) ---
@app.get("/")
async def root():
    return {"message": "DevTools Conglomerate API is operational", "status": "success"}

# --- Stripe Webhook Handler (for all APIs) ---
@app.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.getenv('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle the event (e.g., subscription created, payment succeeded)
    # This will update the user's tier in MongoDB
    # Placeholder for logic
    return JSONResponse(status_code=200, content={"status": "success"})

# ==============================================================================
# XSS SCANNER API - CORE LOGIC
# ==============================================================================
from pydantic import BaseModel
import re
from typing import List, Dict, Any

class XSSScanRequest(BaseModel):
    code: str

@app.post("/scan", summary="Scan code for XSS vulnerabilities")
async def scan_for_xss(request: XSSScanRequest, api_key_info: dict = Depends(get_api_key)):
    """
    Scans provided code for patterns commonly associated with DOM-based and reflected XSS vulnerabilities.

    - **code**: A string of HTML or JavaScript code to analyze.
    """
    
    # Define heuristic patterns for common XSS vulnerabilities
    vulnerability_patterns = {
        "innerHTML_assignment": r"\.innerHTML\s*=\s*[^;]+",  # .innerHTML = ... 
        "document_write_call": r"document\.write\([^)]+\)",  # document.write(...)
        "eval_function_call": r"eval\([^)]+\)",              # eval(...)
        "location_hash_usage": r"location\.hash",            # usage of location.hash
        "script_tag_injection": r"<script[^>]*>",            # <script> tag
        "on_event_handler": r"onerror\s*=|onload\s*=|onclick\s*=",  # onevent=...
        "javascript_protocol": r"javascript:\s*[^\"\']+",    # javascript:...
        "unescaped_user_input": r"\.innerHTML\s*=\s*.*(\+.*userInput|\+.*req\.body|\+.*req\.query)", # Example pattern for unescaped input
    }

    potential_vulnerabilities: List[Dict[str, Any]] = []
    lines = request.code.splitlines()

    for line_num, line in enumerate(lines, start=1):
        for vuln_type, pattern in vulnerability_patterns.items():
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                # Avoid flagging commented-out code (simple heuristic)
                if not re.search(r"^\s*//|^\s*#|/\*.*\*/", line[:match.start()]):
                    potential_vulnerabilities.append({
                        "line": line_num,
                        "vulnerability_type": vuln_type,
                        "snippet": match.group().strip(),
                        "confidence": "medium"  # Heuristic-based detection
                    })

    return {
        "status": "success",
        "vulnerabilities_found": len(potential_vulnerabilities),
        "vulnerabilities": potential_vulnerabilities
    }
