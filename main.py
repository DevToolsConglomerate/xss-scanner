"""
XSS Scanner API - Main Application File

This file contains the FastAPI application for scanning code snippets for XSS vulnerabilities.
It's designed to be easy to understand for junior developers with clear comments and simple structure.

"""

import logging
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient
from contextlib import asynccontextmanager
from typing import Dict, Any
import stripe
import os

from config import config
from models import XSSScanRequest, ScanResponse, HealthResponse
from utils import scanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("xss-scanner")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage database connection lifecycle.
    """
    if config.is_database_enabled:
        app.mongodb_client = MongoClient(config.MONGODB_URI)
        app.database = app.mongodb_client.get_database(config.DATABASE_NAME)
        logger.info("Connected to MongoDB")
    else:
        logger.warning("MongoDB URI not configured; database features disabled")

    if config.is_stripe_enabled:
        stripe.api_key = config.STRIPE_API_KEY
        logger.info("Stripe API key configured")

    yield

    if hasattr(app, "mongodb_client"):
        app.mongodb_client.close()
        logger.info("Disconnected from MongoDB")

app = FastAPI(
    lifespan=lifespan,
    title="XSS Scanner API",
    version="1.0.0",
    description="A fast, automated API to scan HTML and JavaScript code for XSS vulnerabilities"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/", StaticFiles(directory=".", html=True), name="static")

async def get_api_key(x_api_key: str = Header(None)) -> Dict[str, Any]:
    """
    Validate API key from header.
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required in X-API-Key header")

    # For demo purposes, accept any API key if database is not available
    if not hasattr(app, "database"):
        logger.warning("Database not available; accepting any API key for demo")
        return {"key": x_api_key, "is_active": True}

    key_document = app.database.api_keys.find_one({"key": x_api_key, "is_active": True})

    if not key_document:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    return key_document

@app.get("/", response_model=HealthResponse)
async def root():
    """
    Health check endpoint.
    """
    db_connected = hasattr(app, "database")
    return HealthResponse(
        message="XSS Scanner API is operational",
        status="success",
        database_connected=db_connected
    )

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request) -> JSONResponse:
    """
    Handle Stripe webhook events.
    """
    try:
        payload = await request.body()
        signature_header = request.headers.get("stripe-signature")

        event = stripe.Webhook.construct_event(
            payload, signature_header, config.STRIPE_WEBHOOK_SECRET
        )

        # TODO: Handle event types (subscription, payment, etc.)

        return JSONResponse(status_code=200, content={"status": "success", "message": "Webhook processed"})

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

@app.post("/scan", response_model=ScanResponse, summary="Scan code for XSS vulnerabilities")
async def scan_for_xss(
    request: XSSScanRequest,
    api_key_info: Dict[str, Any] = Depends(get_api_key)
):
    """
    Scan code for XSS vulnerabilities.
    """
    try:
        result = scanner.scan_code(request.code)
        return ScanResponse(**result)
    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
