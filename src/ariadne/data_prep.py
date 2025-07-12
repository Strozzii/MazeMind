"""
Handles feature engineering for the ARIADNE machine learning model.

This module defines the logic for transforming raw vulnerability scan data
(lists of CVE and CWE findings) into a structured, numerical feature vector.
This vector serves as the primary input for the model prediction stage,
allowing the machine learning model to understand the risk profile of a
scanned system.
"""

from typing import List, Dict, Union

from src.common.models import CveFinding, CweFinding


def prepare_features(
    all_findings: List[Union[CveFinding, CweFinding]],
    base_score: float
) -> Dict[str, float]:
    """
    Prepares a numerical feature vector using four risk categories.

    This function engineers features based on standard CVSSv3 thresholds.

    Args:
        all_findings: A combined list of all CVE and CWE findings.
        base_score: The base score determined by THESEUS.

    Returns:
        A dictionary of numerical features for the machine learning model.
    """
    finding_count = len(all_findings)

    # Handle the edge case of no findings to avoid division by zero
    if finding_count == 0:
        return {
            "base_score": 0.0,
            "finding_count": 0.0,
            "critical_risk_count": 0.0,
            "high_risk_count": 0.0,
            "medium_risk_count": 0.0,
            "low_risk_count": 0.0,
            "average_score": 0.0,
        }

    # Initialize counters
    critical_risk_count = 0
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    total_score = 0.0

    # Categorize each finding based on its score
    for finding in all_findings:
        total_score += finding.score
        if 9.0 <= finding.score <= 10.0:
            critical_risk_count += 1
        elif 7.0 <= finding.score <= 8.9:
            high_risk_count += 1
        elif 4.0 <= finding.score <= 6.9:
            medium_risk_count += 1
        elif 0.1 <= finding.score <= 3.9:
            low_risk_count += 1

    average_score = total_score / finding_count

    # Assemble the final feature dictionary
    features = {
        "base_score": base_score,
        "finding_count": float(finding_count),
        "critical_risk_count": float(critical_risk_count),
        "high_risk_count": float(high_risk_count),
        "medium_risk_count": float(medium_risk_count),
        "low_risk_count": float(low_risk_count),
        "average_score": average_score,
    }

    return features