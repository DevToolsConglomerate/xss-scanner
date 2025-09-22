"""
XSS Scanner API - Main Application File

This file contains the FastAPI application for scanning code snippets for XSS vulnerabilities.
It's designed to be secure, scalable, and maintainable with proper error handling and validation.
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
from pydantic import ValidationError

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
    Validate API key from header with proper security checks.
    """
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required in X-API-Key header")

    # Always validate against database - no demo bypass
    if not hasattr(app, "database"):
        logger.error("Database not available for API key validation")
        raise HTTPException(status_code=500, detail="Service temporarily unavailable")

    try:
        key_document = app.database.api_keys.find_one({"key": x_api_key, "is_active": True})

        if not key_document:
            logger.warning(f"Invalid API key attempted: {x_api_key[:8]}...")
            raise HTTPException(status_code=401, detail="Invalid or inactive API key")

        return key_document
    except Exception as e:
        logger.error(f"Database error during API key validation: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

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
    Handle Stripe webhook events with proper validation.
    """
    try:
        payload = await request.body()
        signature_header = request.headers.get("stripe-signature")

        if not signature_header:
            raise HTTPException(status_code=400, detail="Missing stripe signature")

        event = stripe.Webhook.construct_event(
            payload, signature_header, config.STRIPE_WEBHOOK_SECRET
        )

        # TODO: Handle event types (subscription, payment, etc.)
        logger.info(f"Stripe webhook processed: {event['type']}")

        return JSONResponse(status_code=200, content={"status": "success", "message": "Webhook processed"})

    except ValueError as e:
        logger.error(f"Invalid webhook payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid webhook signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        raise HTTPException(status_code=500, detail="Webhook processing failed")

@app.post("/scan", response_model=ScanResponse, summary="Scan code for XSS vulnerabilities")
async def scan_for_xss(
    request: XSSScanRequest,
    api_key_info: Dict[str, Any] = Depends(get_api_key)
):
    """
    Scan code for XSS vulnerabilities with comprehensive validation and error handling.
    """
    try:
        # Additional validation beyond Pydantic
        if len(request.code) > config.MAX_CODE_LENGTH:
            raise HTTPException(
                status_code=413,
                detail=f"Code too large. Maximum size: {config.MAX_CODE_LENGTH} characters"
            )

        if not request.code.strip():
            raise HTTPException(status_code=400, detail="Code cannot be empty")

        # Log scan attempt (without exposing sensitive data)
        logger.info(f"Scan initiated by user: {api_key_info.get('user_id', 'unknown')}")

        result = scanner.scan_code(request.code)
        return ScanResponse(**result)

    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        raise HTTPException(status_code=422, detail=f"Invalid input: {str(e)}")

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise

    except Exception as e:
        logger.error(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during scanning")
