"""
Defines the central data models for the MazeMind project.

These models are used by all components (THESEUS, ARIADNE)
to ensure a consistent and validated data flow.
"""

from datetime import datetime, timezone
from typing import List

from pydantic import BaseModel, Field


class CweInfo(BaseModel):
    """
    Encapsulates information about a Common Weakness Enumeration (CWE).
    """
    id: str = Field(..., description="CWE identifier, e.g., 'CWE-89'.")
    name: str = Field(..., description="Official name of the weakness, e.g., 'SQL Injection'.")


class CveFinding(BaseModel):
    """
    Represents a single CVE-based vulnerability found during a scan.
    """
    id: str = Field(..., description="A unique ID for the finding, e.g., one assigned by the scanner.")
    cve_id: str = Field(..., description="The official CVE ID, e.g., 'CVE-2021-44228'.")
    description: str = Field(..., description="A brief description of the vulnerability.")
    score: float = Field(..., ge=0.0, le=10.0, description="The CVSS score for the vulnerability.")
    location: str = Field(..., description="The location of the vulnerability, e.g., an IP address or URL.")


class CweFinding(BaseModel):
    """
    Represents a single CWE-based weakness found during a scan.
    """
    id: str = Field(..., description="A unique ID for the finding, e.g., one assigned by the scanner.")
    cwe: CweInfo = Field(..., description="Detailed information about the type of weakness (CWE).")
    description: str = Field(..., description="A brief description of the weakness found.")
    score: float = Field(..., ge=0.0, le=10.0, description="The calculated CWSS score for the weakness.")
    location: str = Field(..., description="The location of the weakness, e.g., a specific file or code line.")


class ScanResult(BaseModel):
    """
    Represents the result of a complete vulnerability scan for a company.

    It contains separate lists for CVE-based and CWE-based findings.
    """
    company_id: str = Field(..., description="Unique identifier for the scanned company.")
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the scan (in UTC)."
    )
    cve_findings: List[CveFinding] = Field(..., description="A list of all CVE-based vulnerability findings.")
    cwe_findings: List[CweFinding] = Field(..., description="A list of all CWE-based weakness findings.")


class CyberRiskScore(BaseModel):
    """
    Represents the final output: the CyberRiskScore (CRS).
    """
    company_id: str = Field(..., description="Unique identifier for the assessed company.")
    crs_score: float = Field(..., ge=0.0, le=10.0, description="The final CyberRiskScore (0 = unlikely, 10 = very likely).")
    base_score: float = Field(..., ge=0.0, le=10.0, description="The base score determined by THESEUS.")
    key_risk_factors: List[str] = Field(..., description="A list of the finding IDs that most influenced the score.")
    calculation_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the CRS calculation (in UTC)."
    )

    def __str__(self) -> str:
        """Returns a user-friendly string representation of the score."""
        return f"<CyberRiskScore for '{self.company_id}': {self.crs_score:.2f}/10.0>"