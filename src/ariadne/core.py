"""
The core orchestration logic for the ARIADNE module.

This module connects the feature preparation and model prediction steps
to calculate the final CyberRiskScore.
"""
from typing import List

from src.common.models import ScanResult, CyberRiskScore
from src.ariadne.data_prep import prepare_features
from src.ariadne.model_predict import predict_risk_adjustment


def generate_final_score(scan_result: ScanResult, base_score: float) -> CyberRiskScore:
    """
    Generates the final, model-adjusted CyberRiskScore.

    This function orchestrates the ARIADNE workflow:
    1. Prepares features from the scan data.
    2. Gets a risk adjustment factor from the ML model.
    3. Calculates the final score by applying the adjustment to the base score.
    4. Constructs and returns the final CyberRiskScore object.

    Args:
        scan_result: The full result data from the vulnerability scan.
        base_score: The initial base score calculated by THESEUS.

    Returns:
        A complete CyberRiskScore object with the final calculated score.
    """
    # 1. Combine all findings into a single list
    all_findings = scan_result.cve_findings + scan_result.cwe_findings

    # 2. Prepare the feature vector for the model
    features = prepare_features(all_findings, base_score)

    # 3. Get the risk adjustment factor from the model prediction
    risk_adjustment = predict_risk_adjustment(features)

    # 4. Calculate the final score
    # The adjustment factor (0-1) scales the remaining score range (10 - base_score)
    final_score = base_score + (10.0 - base_score) * risk_adjustment
    # Ensure the score does not exceed 10.0 due to floating point inaccuracies
    final_score = min(10.0, final_score)

    # 5. Determine the key risk factors
    key_risk_factors: List[str] = []
    if all_findings:
        # For now, we define the key risk factor as the finding with the highest score
        key_finding = max(all_findings, key=lambda finding: finding.score)
        key_risk_factors.append(key_finding.id)

    # 6. Create and return the final CyberRiskScore object
    crs_object = CyberRiskScore(
        company_id=scan_result.company_id,
        crs_score=final_score,
        base_score=base_score,
        key_risk_factors=key_risk_factors,
    )

    return crs_object