import unittest

from src.common.models import CveFinding, CweFinding, CweInfo
from src.ariadne.data_prep import prepare_features


class TestAriadneDataPrep(unittest.TestCase):
    """
    Tests the feature engineering logic in the data_prep module.
    """

    def setUp(self):
        """Set up a reusable CWEInfo object for tests."""
        self.cwe_info = CweInfo(id="CWE-79", name="Cross-site Scripting")

    def test_prepare_features_comprehensive_scenario(self):
        """
        Tests feature calculation with a mix of findings across all risk levels.
        """
        base_score = 9.5
        all_findings = [
            # 1 Critical
            CveFinding(id="cve1", cve_id="CVE-1", score=9.5, description="d", location="l"),
            # 2 High
            CveFinding(id="cve2", cve_id="CVE-2", score=8.8, description="d", location="l"),
            CweFinding(id="cwe1", cwe=self.cwe_info, score=7.0, description="d", location="l"),
            # 3 Medium
            CveFinding(id="cve3", cve_id="CVE-3", score=6.5, description="d", location="l"),
            CveFinding(id="cve4", cve_id="CVE-4", score=5.0, description="d", location="l"),
            CweFinding(id="cwe2", cwe=self.cwe_info, score=4.0, description="d", location="l"),
            # 1 Low
            CveFinding(id="cve5", cve_id="CVE-5", score=3.2, description="d", location="l"),
            # 1 with no risk score (0.0)
            CveFinding(id="cve6", cve_id="CVE-6", score=0.0, description="d", location="l"),
        ]

        # Expected calculations
        # total_score = 9.5 + 8.8 + 7.0 + 6.5 + 5.0 + 4.0 + 3.2 + 0.0 = 44.0
        # average_score = 44.0 / 8 = 5.5
        expected_features = {
            "base_score": 9.5,
            "finding_count": 8.0,
            "critical_risk_count": 1.0,
            "high_risk_count": 2.0,
            "medium_risk_count": 3.0,
            "low_risk_count": 1.0,
            "average_score": 5.5,
        }

        features = prepare_features(all_findings, base_score)

        self.assertDictEqual(features, expected_features)

    def test_prepare_features_no_findings(self):
        """
        Tests the behavior when there are no findings to process.
        """
        base_score = 0.0
        all_findings = []

        expected_features = {
            "base_score": 0.0,
            "finding_count": 0.0,
            "critical_risk_count": 0.0,
            "high_risk_count": 0.0,
            "medium_risk_count": 0.0,
            "low_risk_count": 0.0,
            "average_score": 0.0,
        }

        features = prepare_features(all_findings, base_score)

        self.assertDictEqual(features, expected_features)

    def test_prepare_features_boundary_conditions(self):
        """
        Tests that scores on the exact boundaries of thresholds are categorized correctly.
        """
        base_score = 9.0
        all_findings = [
            CveFinding(id="c1", cve_id="CVE-1", score=9.0, description="d", location="l"),  # Critical
            CveFinding(id="c2", cve_id="CVE-2", score=8.9, description="d", location="l"),  # High
            CveFinding(id="c3", cve_id="CVE-3", score=7.0, description="d", location="l"),  # High
            CveFinding(id="c4", cve_id="CVE-4", score=6.9, description="d", location="l"),  # Medium
            CveFinding(id="c5", cve_id="CVE-5", score=4.0, description="d", location="l"),  # Medium
            CveFinding(id="c6", cve_id="CVE-6", score=3.9, description="d", location="l"),  # Low
            CveFinding(id="c7", cve_id="CVE-7", score=0.1, description="d", location="l"),  # Low
        ]

        features = prepare_features(all_findings, base_score)

        self.assertEqual(features["critical_risk_count"], 1.0)
        self.assertEqual(features["high_risk_count"], 2.0)
        self.assertEqual(features["medium_risk_count"], 2.0)
        self.assertEqual(features["low_risk_count"], 2.0)


if __name__ == '__main__':
    unittest.main()