import unittest
from unittest.mock import patch, MagicMock

import numpy as np
import importlib

from src.common.models import CveFinding, CweFinding, CweInfo
from src.ariadne.data_prep import prepare_features
from src.ariadne import model_predict


class TestAriadneDataPrep(unittest.TestCase):
    """
    Tests the feature engineering logic in the data_prep module.
    (This class is from the previous step and remains unchanged)
    """

    # ... previous tests for data_prep.py ...
    def setUp(self):
        """Set up a reusable CWEInfo object for tests."""
        self.cwe_info = CweInfo(id="CWE-79", name="Cross-site Scripting")

    def test_prepare_features_comprehensive_scenario(self):
        """
        Tests feature calculation with a mix of findings across all risk levels.
        """
        base_score = 9.5
        all_findings = [
            CveFinding(id="cve1", cve_id="CVE-1", score=9.5, description="d", location="l"),
            CveFinding(id="cve2", cve_id="CVE-2", score=8.8, description="d", location="l"),
            CweFinding(id="cwe1", cwe=self.cwe_info, score=7.0, description="d", location="l"),
            CveFinding(id="cve3", cve_id="CVE-3", score=6.5, description="d", location="l"),
            CveFinding(id="cve4", cve_id="CVE-4", score=5.0, description="d", location="l"),
            CweFinding(id="cwe2", cwe=self.cwe_info, score=4.0, description="d", location="l"),
            CveFinding(id="cve5", cve_id="CVE-5", score=3.2, description="d", location="l"),
            CveFinding(id="cve6", cve_id="CVE-6", score=0.0, description="d", location="l"),
        ]
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


class TestAriadneModelPredict(unittest.TestCase):
    """
    Tests the prediction logic in the model_predict module.
    """

    def setUp(self):
        """Set up a standard features dictionary for testing."""
        self.sample_features = {
            "base_score": 8.0, "finding_count": 10.0, "critical_risk_count": 0.0,
            "high_risk_count": 1.0, "medium_risk_count": 5.0, "low_risk_count": 4.0,
            "average_score": 4.5,
        }

    @patch('src.ariadne.model_predict.joblib.load')
    def test_predict_risk_adjustment_success(self, mock_load):
        """
        Tests a successful prediction using a mocked model.
        """
        # 1. Configure the mock model
        mock_model = MagicMock()
        # Set the return value for the .predict_proba() method
        mock_model.predict_proba.return_value = np.array([[0.2, 0.8]])  # [prob_class_0, prob_class_1]
        # Make the mock loader return our mock model
        mock_load.return_value = mock_model

        # 2. Reload the module to ensure it uses our mock
        importlib.reload(model_predict)

        # 3. Call the function and assert the result
        risk_adjustment = model_predict.predict_risk_adjustment(self.sample_features)

        # We expect the probability of class 1
        self.assertEqual(risk_adjustment, 0.8)

    @patch('src.ariadne.model_predict.joblib.load', side_effect=FileNotFoundError)
    def test_predict_when_model_file_not_found(self, mock_load):
        """
        Tests that the function returns 0.0 if the model file is not found.
        """
        # Reload the module. The patch will make the import fail internally.
        importlib.reload(model_predict)

        risk_adjustment = model_predict.predict_risk_adjustment(self.sample_features)

        # The function should gracefully handle the error and return 0.0
        self.assertEqual(risk_adjustment, 0.0)

    @patch('src.ariadne.model_predict.joblib.load')
    def test_predict_with_missing_feature(self, mock_load):
        """
        Tests that the function returns 0.0 if a feature is missing.
        """
        # Configure a working mock model
        mock_model = MagicMock()
        mock_load.return_value = mock_model
        importlib.reload(model_predict)

        # Remove a key from the features dictionary
        del self.sample_features["average_score"]

        risk_adjustment = model_predict.predict_risk_adjustment(self.sample_features)

        # The function should catch the KeyError and return 0.0
        self.assertEqual(risk_adjustment, 0.0)


if __name__ == '__main__':
    unittest.main()