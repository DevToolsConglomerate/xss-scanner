"""
Pydantic models for XSS Scanner API
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class XSSScanRequest(BaseModel):
    """
    Model for the XSS scan request.

    Attributes:
        code: The HTML/JavaScript code to scan for vulnerabilities
    """
    code: str = Field(..., min_length=1, description="The code to scan for XSS vulnerabilities")

class Vulnerability(BaseModel):
    """
    Model for a single vulnerability finding.

    Attributes:
        line: Line number where vulnerability was found
        vulnerability_type: Type of vulnerability detected
        snippet: The actual code snippet that triggered the detection
        confidence: Confidence level of the detection
        description: Human-readable description of the vulnerability
    """
    line: int
    vulnerability_type: str
    snippet: str
    confidence: str
    description: str

class ScanResponse(BaseModel):
    """
    Model for the scan response.

    Attributes:
        status: Status of the scan operation
        vulnerabilities_found: Number of vulnerabilities detected
        vulnerabilities: List of detected vulnerabilities
        message: Human-readable message about the scan results
    """
    status: str
    vulnerabilities_found: int
    vulnerabilities: List[Vulnerability]
    message: str

class HealthResponse(BaseModel):
    """
    Model for health check response.

    Attributes:
        message: Health status message
        status: Status indicator
        database_connected: Whether database is connected
    """
    message: str
    status: str
    database_connected: Optional[bool] = None

class APIKeyDocument(BaseModel):
    """
    Model for API key document from database.

    Attributes:
        key: The API key string
        is_active: Whether the key is active
        user_id: Associated user ID
        created_at: Creation timestamp
    """
    key: str
    is_active: bool
    user_id: Optional[str] = None
    created_at: Optional[str] = None
