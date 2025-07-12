import unittest
from datetime import datetime

from pydantic import ValidationError

from src.common.models import CweInfo, CveFinding, CweFinding, ScanResult, CyberRiskScore


class TestDataModels(unittest.TestCase):
    """
    Tests the data models from src/common/models.py.
    """

    def setUp(self):
        """Set up a reusable CWEInfo object for tests."""
        self.cwe_info = CweInfo(id="CWE-79", name="Cross-site Scripting")

    def test_cweinfo_creation(self):
        """Tests the successful and unsuccessful creation of CWEInfo."""
        self.assertEqual(self.cwe_info.id, "CWE-79")
        self.assertEqual(self.cwe_info.name, "Cross-site Scripting")

        with self.assertRaises(ValidationError):
            CweInfo(id="CWE-79")  # 'name' is missing

    def test_cve_finding_creation(self):
        """Tests the successful creation and validation of a CveFinding."""
        finding = CveFinding(
            id="scanner-cve-001",
            cve_id="CVE-2025-10001",
            description="A critical CVE finding.",
            score=9.8,
            location="server-alpha"
        )
        self.assertEqual(finding.cve_id, "CVE-2025-10001")
        self.assertEqual(finding.score, 9.8)

        # Test required fields
        with self.assertRaises(ValidationError):
            CveFinding(id="f1", description="d", score=9.0, location="l")  # cve_id is missing

    def test_cwe_finding_creation(self):
        """Tests the successful creation and validation of a CweFinding."""
        finding = CweFinding(
            id="scanner-cwe-001",
            cwe=self.cwe_info,
            description="A critical CWE finding.",
            score=6.5,
            location="app/login.py"
        )
        self.assertEqual(finding.cwe.id, "CWE-79")
        self.assertEqual(finding.score, 6.5)

        # Test required fields
        with self.assertRaises(ValidationError):
            CweFinding(id="f1", description="d", score=6.0, location="l")  # cwe is missing

    def test_score_validation_for_findings(self):
        """Tests that the score for all finding types must be between 0.0 and 10.0."""
        with self.assertRaises(ValidationError, msg="CVE score > 10.0 should fail"):
            CveFinding(id="f1", cve_id="c1", description="d", score=10.1, location="l")

        with self.assertRaises(ValidationError, msg="CWE score < 0.0 should fail"):
            CweFinding(id="f2", cwe=self.cwe_info, description="d", score=-0.1, location="l")

    def test_scan_result_creation(self):
        """Tests the creation of a ScanResult with separate CVE and CWE lists."""
        cve_finding = CveFinding(id="cve-1", cve_id="CVE-2025-20001", description="d1", score=7.0, location="l1")
        cwe_finding = CweFinding(id="cwe-1", cwe=self.cwe_info, description="d2", score=5.0, location="l2")

        scan = ScanResult(
            company_id="company-abc-123",
            cve_findings=[cve_finding],
            cwe_findings=[cwe_finding]
        )

        self.assertEqual(scan.company_id, "company-abc-123")
        self.assertEqual(len(scan.cve_findings), 1)
        self.assertEqual(len(scan.cwe_findings), 1)
        self.assertEqual(scan.cve_findings[0].cve_id, "CVE-2025-20001")
        self.assertEqual(scan.cwe_findings[0].cwe.id, "CWE-79")
        self.assertIsInstance(scan.scan_timestamp, datetime)
        self.assertIsNotNone(scan.scan_timestamp.tzinfo)

    def test_cyber_risk_score_creation_and_str(self):
        """Tests the creation and string representation of the CyberRiskScore."""
        crs = CyberRiskScore(
            company_id="company-xyz-456",
            crs_score=8.2,
            base_score=7.1,
            key_risk_factors=["scanner-cve-001"]
        )
        self.assertEqual(crs.crs_score, 8.2)

        expected_str = "<CyberRiskScore for 'company-xyz-456': 8.20/10.0>"
        self.assertEqual(str(crs), expected_str)


if __name__ == '__main__':
    unittest.main()