import unittest
from unittest.mock import patch

from src.common.models import ScanResult, CveFinding, CweFinding, CweInfo, CyberRiskScore
from src.theseus.core import determine_base_score
from src.ariadne.core import generate_final_score


class TestIntegrationPipeline(unittest.TestCase):
    """
    Tests the full end-to-end integration of the THESEUS and ARIADNE modules.
    """

    @patch('src.ariadne.core.predict_risk_adjustment')
    def test_full_pipeline_flow(self, mock_predict_adjustment):
        """
        Tests the entire calculation pipeline from ScanResult to CyberRiskScore,
        using a mocked model prediction for consistency.
        """
        # --- 1. Arrange ---
        # Configure the ML model's prediction to be a fixed value
        mock_predict_adjustment.return_value = 0.5  # 50% risk adjustment

        # Create a sample scan result to process
        scan_result = ScanResult(
            company_id="Integrated Test Corp",
            cve_findings=[
                CveFinding(id="cve-high", cve_id="CVE-1", score=8.0, description="d", location="l"),
            ],
            cwe_findings=[
                CweFinding(id="cwe-low", cwe=CweInfo(id="CWE-1", name="n"), score=4.5, description="d", location="l")
            ]
        )

        # --- 2. Act ---
        # First, run the THESEUS module
        base_score = determine_base_score(scan_result)

        # Then, run the ARIADNE module with the output from THESEUS
        final_crs_object = generate_final_score(scan_result, base_score)

        # --- 3. Assert ---
        # Check the intermediate result from THESEUS
        self.assertEqual(base_score, 8.0)

        # Check the final CyberRiskScore object from ARIADNE
        self.assertIsInstance(final_crs_object, CyberRiskScore)
        self.assertEqual(final_crs_object.company_id, "Integrated Test Corp")
        self.assertEqual(final_crs_object.base_score, 8.0)

        # Verify the final score calculation: 8.0 + (10.0 - 8.0) * 0.5 = 9.0
        self.assertAlmostEqual(final_crs_object.crs_score, 9.0)


if __name__ == '__main__':
    unittest.main()