"""This module takes care of the calculations and aggregation of vulnerabilities and provides the CRS."""

from src.common.models import ScanResult


def determine_base_score(scan_result: ScanResult) -> float:
    """
    Determines the base score from a scan result.

    The base score is the highest score found among all CVE and CWE findings.

    Args:
        scan_result: The result object from the vulnerability scan.

    Returns:
        The highest score found, representing the base score. Returns 0.0 if no findings exist.
    """
    all_findings = scan_result.cve_findings + scan_result.cwe_findings

    if not all_findings:
        return 0.0

    base_score = max(finding.score for finding in all_findings)

    return base_score