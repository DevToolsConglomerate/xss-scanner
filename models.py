"""
Pydantic models for XSS Scanner API with enhanced validation
"""
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional
import re

class XSSScanRequest(BaseModel):
    """
    Model for the XSS scan request with comprehensive validation.

    Attributes:
        code: The HTML/JavaScript code to scan for vulnerabilities
    """
    code: str = Field(..., min_length=1, max_length=100000, description="The code to scan for XSS vulnerabilities")

    @validator('code')
    def validate_code(cls, v):
        """Validate the code input for security and content."""
        if not v.strip():
            raise ValueError('Code cannot be empty or only whitespace')

        # Check for extremely long lines that might indicate malicious content
        lines = v.split('\n')
        if any(len(line) > 10000 for line in lines):
            raise ValueError('Code contains lines that are too long')

        # Basic content validation - reject obviously malicious content
        dangerous_patterns = [
            r'<script[^>]*>.*alert.*</script>',
            r'javascript:.*alert',
            r'eval\(.*alert',
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                logger.warning("Potentially malicious code detected in scan request")
                # Don't reject, just log - let the scanner handle it

        return v

class Vulnerability(BaseModel):
    """
    Model for a single vulnerability finding with enhanced metadata.

    Attributes:
        line: Line number where vulnerability was found
        vulnerability_type: Type of vulnerability detected
        snippet: The actual code snippet that triggered the detection
        confidence: Confidence level of the detection
        description: Human-readable description of the vulnerability
        severity: Severity level of the vulnerability
    """
    line: int = Field(..., gt=0, description="Line number where vulnerability was found")
    vulnerability_type: str = Field(..., description="Type of vulnerability detected")
    snippet: str = Field(..., description="The actual code snippet that triggered the detection")
    confidence: str = Field(..., description="Confidence level of the detection")
    description: str = Field(..., description="Human-readable description of the vulnerability")
    severity: str = Field(default="medium", description="Severity level of the vulnerability")

class ScanResponse(BaseModel):
    """
    Model for the scan response with comprehensive metadata.

    Attributes:
        status: Status of the scan operation
        vulnerabilities_found: Number of vulnerabilities detected
        vulnerabilities: List of detected vulnerabilities
        message: Human-readable message about the scan results
        scan_duration: Time taken for the scan in seconds
        code_length: Length of the scanned code
    """
    status: str = Field(..., description="Status of the scan operation")
    vulnerabilities_found: int = Field(..., ge=0, description="Number of vulnerabilities detected")
    vulnerabilities: List[Vulnerability] = Field(..., description="List of detected vulnerabilities")
    message: str = Field(..., description="Human-readable message about the scan results")
    scan_duration: Optional[float] = Field(None, description="Time taken for the scan in seconds")
    code_length: Optional[int] = Field(None, description="Length of the scanned code")

class HealthResponse(BaseModel):
    """
    Model for health check response with detailed system information.

    Attributes:
        message: Health status message
        status: Status indicator
        database_connected: Whether database is connected
        timestamp: Time of the health check
        version: API version
    """
    message: str = Field(..., description="Health status message")
    status: str = Field(..., description="Status indicator")
    database_connected: Optional[bool] = Field(None, description="Whether database is connected")
    timestamp: Optional[str] = Field(None, description="Time of the health check")
    version: Optional[str] = Field(None, description="API version")

class APIKeyDocument(BaseModel):
    """
    Model for API key document from database with enhanced validation.

    Attributes:
        key: The API key string
        is_active: Whether the key is active
        user_id: Associated user ID
        created_at: Creation timestamp
        last_used: Last usage timestamp
        usage_count: Number of times the key has been used
    """
    key: str = Field(..., description="The API key string")
    is_active: bool = Field(..., description="Whether the key is active")
    user_id: Optional[str] = Field(None, description="Associated user ID")
    created_at: Optional[str] = Field(None, description="Creation timestamp")
    last_used: Optional[str] = Field(None, description="Last usage timestamp")
    usage_count: Optional[int] = Field(0, description="Number of times the key has been used")

    @validator('key')
    def validate_api_key(cls, v):
        """Validate API key format."""
        if not v or len(v) < 16:
            raise ValueError('API key must be at least 16 characters long')
        return v

class ErrorResponse(BaseModel):
    """
    Model for error responses with detailed information.

    Attributes:
        error: Error type
        message: Human-readable error message
        detail: Additional error details
        timestamp: Time of the error
    """
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Human-readable error message")
    detail: Optional[str] = Field(None, description="Additional error details")
    timestamp: Optional[str] = Field(None, description="Time of the error")
