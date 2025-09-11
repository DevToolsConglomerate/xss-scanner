"""
XSS Scanner API - Main Application File

This file contains the FastAPI application for scanning code snippets for XSS vulnerabilities.
It's designed to be easy to understand for junior developers with clear comments and simple structure.

Author: BLACKBOXAI
Version: 1.0.0
"""

# Import required libraries
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo import MongoClient
from contextlib import asynccontextmanager
import os
import stripe
import logging
from typing import Dict, Any, List

# ==============================================================================
# CONFIGURATION SECTION
# ==============================================================================

# Get environment variables for database and payment processing
MONGODB_URI = os.getenv("MONGODB_URI")
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")

# Set up Stripe API key for payment processing
if STRIPE_API_KEY:
    stripe.api_key = STRIPE_API_KEY

# ==============================================================================
# DATABASE LIFECYCLE MANAGEMENT
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the database connection lifecycle.

    This function runs when the app starts and stops.
    It connects to MongoDB on startup and closes the connection on shutdown.
    """
    # Startup: Connect to MongoDB database
    if MONGODB_URI:
        app.mongodb_client = MongoClient(MONGODB_URI)
        app.database = app.mongodb_client.get_database("devtools_conglomerate")
        logging.info("Successfully connected to MongoDB")
    else:
        logging.warning("MONGODB_URI not found - database features will be disabled")

    # This is where the app runs
    yield

    # Shutdown: Close database connection
    if hasattr(app, 'mongodb_client'):
        app.mongodb_client.close()
        logging.info("Disconnected from MongoDB")

# ==============================================================================
# FASTAPI APPLICATION SETUP
# ==============================================================================

# Create the FastAPI application with metadata
app = FastAPI(
    lifespan=lifespan,
    title="XSS Scanner API",
    version="1.0.0",
    description="A fast, automated API to scan HTML and JavaScript code for XSS vulnerabilities"
)

# Add CORS middleware to allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow requests from any origin
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# ==============================================================================
# AUTHENTICATION FUNCTIONS
# ==============================================================================

async def get_api_key(x_api_key: str = Header(None)) -> Dict[str, Any]:
    """
    Validates the API key from the request header.

    Args:
        x_api_key: The API key from the X-API-Key header

    Returns:
        The API key document from the database

    Raises:
        HTTPException: If API key is missing or invalid
    """
    # Check if API key was provided in the header
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key is required. Please provide it in the X-API-Key header."
        )

    # Check if the database is available
    if not hasattr(app, 'database'):
        raise HTTPException(
            status_code=503,
            detail="Database not available. Please check your MongoDB connection."
        )

    # Look up the API key in the database
    key_document = app.database.api_keys.find_one({
        "key": x_api_key,
        "is_active": True
    })

    # If key not found or inactive, return error
    if not key_document:
        raise HTTPException(
            status_code=401,
            detail="Invalid or inactive API key. Please check your key and try again."
        )

    return key_document

# ==============================================================================
# GENERAL API ENDPOINTS
# ==============================================================================

@app.get("/")
async def root() -> Dict[str, str]:
    """
    Health check endpoint to verify the API is running.

    Returns:
        A simple message confirming the API is operational
    """
    return {
        "message": "XSS Scanner API is operational",
        "status": "success"
    }

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request) -> JSONResponse:
    """
    Handles Stripe webhook events for payment processing.

    This endpoint receives notifications from Stripe about payment events
    and updates the user's subscription status in the database.

    Args:
        request: The incoming webhook request from Stripe

    Returns:
        Success confirmation
    """
    try:
        # Get the raw request body and signature
        payload = await request.body()
        signature_header = request.headers.get('stripe-signature')

        # Verify the webhook signature for security
        event = stripe.Webhook.construct_event(
            payload,
            signature_header,
            os.getenv('STRIPE_WEBHOOK_SECRET')
        )

        # TODO: Add logic to handle different event types
        # (e.g., subscription created, payment succeeded, etc.)
        # This would update the user's tier in the database

        return JSONResponse(
            status_code=200,
            content={"status": "success", "message": "Webhook processed"}
        )

    except ValueError as error:
        # Invalid payload
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    except stripe.error.SignatureVerificationError as error:
        # Invalid signature
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

# ==============================================================================
# XSS SCANNER API - CORE LOGIC
# ==============================================================================

# Import additional libraries needed for XSS scanning
from pydantic import BaseModel
import re
from typing import List, Dict, Any

# Data model for the scan request
class XSSScanRequest(BaseModel):
    """
    Model for the XSS scan request.

    Attributes:
        code: The HTML/JavaScript code to scan for vulnerabilities
    """
    code: str

def get_vulnerability_patterns() -> Dict[str, str]:
    """
    Returns a dictionary of regex patterns for common XSS vulnerabilities.

    Each pattern is designed to detect potentially dangerous code patterns
    that could lead to cross-site scripting attacks.

    Returns:
        Dictionary mapping vulnerability names to regex patterns
    """
    return {
        "innerHTML_assignment": r"\.innerHTML\s*=\s*[^;]+",  # Direct assignment to innerHTML
        "document_write_call": r"document\.write\([^)]+\)",  # document.write() calls
        "eval_function_call": r"eval\([^)]+\)",              # eval() function calls
        "location_hash_usage": r"location\.hash",            # Accessing location.hash
        "script_tag_injection": r"<script[^>]*>",            # Script tag injection
        "on_event_handler": r"onerror\s*=|onload\s*=|onclick\s*=",  # Inline event handlers
        "javascript_protocol": r"javascript:\s*[^\"\']+",    # javascript: protocol in URLs
        "unescaped_user_input": r"\.innerHTML\s*=\s*.*(\+.*userInput|\+.*req\.body|\+.*req\.query)", # Unescaped user input
    }

def is_commented_line(line: str, match_position: int) -> bool:
    """
    Checks if a potential vulnerability match is inside a comment.

    This helps avoid false positives from commented-out code.

    Args:
        line: The line of code being analyzed
        match_position: The position where the match was found

    Returns:
        True if the match appears to be in a comment, False otherwise
    """
    # Check for common comment patterns before the match position
    comment_patterns = [
        r"^\s*//",      # Single line comment (//)
        r"^\s*#",       # Python-style comment (#)
        r"/\*.*\*/",    # Multi-line comment (/* */)
    ]

    # Look at the text before the match
    text_before_match = line[:match_position]

    for pattern in comment_patterns:
        if re.search(pattern, text_before_match):
            return True

    return False

def scan_line_for_vulnerabilities(
    line: str,
    line_number: int,
    patterns: Dict[str, str]
) -> List[Dict[str, Any]]:
    """
    Scans a single line of code for XSS vulnerabilities.

    Args:
        line: The line of code to scan
        line_number: The line number in the original code
        patterns: Dictionary of vulnerability patterns to check

    Returns:
        List of found vulnerabilities in this line
    """
    found_vulnerabilities = []

    for vulnerability_name, pattern in patterns.items():
        # Find all matches of this pattern in the line
        matches = re.finditer(pattern, line, re.IGNORECASE)

        for match in matches:
            # Skip if this match appears to be in a comment
            if not is_commented_line(line, match.start()):
                found_vulnerabilities.append({
                    "line": line_number,
                    "vulnerability_type": vulnerability_name,
                    "snippet": match.group().strip(),
                    "confidence": "medium"  # Heuristic-based detection
                })

    return found_vulnerabilities

@app.post("/scan", summary="Scan code for XSS vulnerabilities")
async def scan_for_xss(
    request: XSSScanRequest,
    api_key_info: Dict[str, Any] = Depends(get_api_key)
) -> Dict[str, Any]:
    """
    Scans provided code for patterns commonly associated with XSS vulnerabilities.

    This endpoint analyzes HTML and JavaScript code to identify potential
    security vulnerabilities that could lead to cross-site scripting attacks.

    Args:
        request: The scan request containing the code to analyze
        api_key_info: API key information (automatically validated)

    Returns:
        Dictionary containing scan results with found vulnerabilities
    """
    try:
        # Get the patterns we'll use to detect vulnerabilities
        vulnerability_patterns = get_vulnerability_patterns()

        # Split the code into individual lines for analysis
        code_lines = request.code.splitlines()

        # List to store all found vulnerabilities
        all_vulnerabilities = []

        # Scan each line of code
        for line_number, line in enumerate(code_lines, start=1):
            line_vulnerabilities = scan_line_for_vulnerabilities(
                line, line_number, vulnerability_patterns
            )
            all_vulnerabilities.extend(line_vulnerabilities)

        # Return the scan results
        return {
            "status": "success",
            "vulnerabilities_found": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "message": f"Scan completed. Found {len(all_vulnerabilities)} potential vulnerabilities."
        }

    except Exception as error:
        # Handle any unexpected errors during scanning
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred during scanning: {str(error)}"
        )
