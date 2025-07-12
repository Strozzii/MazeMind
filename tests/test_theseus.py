import unittest

from src.common.models import ScanResult, CveFinding, CweFinding, CweInfo
from src.theseus.core import determine_base_score


class TestTheseusCore(unittest.TestCase):
    """
    Tests the core logic of the THESEUS module.
    """

    def setUp(self):
        """Set up reusable test objects."""
        self.cwe_info_xss = CweInfo(id="CWE-79", name="Cross-site Scripting")
        self.cwe_info_sqli = CweInfo(id="CWE-89", name="SQL Injection")

    def test_base_score_when_highest_is_cve(self):
        """
        Tests that the highest score is correctly identified when it's a CVE.
        """
        cve_findings = [
            CveFinding(id="cve1", cve_id="CVE-2025-001", description="High risk", score=9.8, location="server-a"),
            CveFinding(id="cve2", cve_id="CVE-2025-002", description="Low risk", score=4.3, location="server-b"),
        ]
        cwe_findings = [
            CweFinding(id="cwe1", cwe=self.cwe_info_xss, description="Medium risk", score=6.5, location="app.js"),
        ]
        scan_result = ScanResult(company_id="c1", cve_findings=cve_findings, cwe_findings=cwe_findings)

        base_score = determine_base_score(scan_result)
        self.assertEqual(base_score, 9.8)

    def test_base_score_when_highest_is_cwe(self):
        """
        Tests that the highest score is correctly identified when it's a CWE.
        """
        cve_findings = [
            CveFinding(id="cve1", cve_id="CVE-2025-003", description="Medium risk", score=5.0, location="server-c"),
        ]
        cwe_findings = [
            CweFinding(id="cwe1", cwe=self.cwe_info_sqli, description="High risk", score=8.5, location="db.py"),
            CweFinding(id="cwe2", cwe=self.cwe_info_xss, description="Low risk", score=3.0, location="ui.js"),
        ]
        scan_result = ScanResult(company_id="c2", cve_findings=cve_findings, cwe_findings=cwe_findings)

        base_score = determine_base_score(scan_result)
        self.assertEqual(base_score, 8.5)

    def test_base_score_with_no_findings(self):
        """
        Tests that the base score is 0.0 when no findings are present.
        """
        scan_result = ScanResult(company_id="c3", cve_findings=[], cwe_findings=[])
        base_score = determine_base_score(scan_result)
        self.assertEqual(base_score, 0.0)

    def test_base_score_with_only_cve_findings(self):
        """
        Tests calculation when only one list (CVEs) is populated.
        """
        cve_findings = [
            CveFinding(id="cve1", cve_id="CVE-2025-004", description="A finding", score=7.1, location="server-d"),
        ]
        scan_result = ScanResult(company_id="c4", cve_findings=cve_findings, cwe_findings=[])
        base_score = determine_base_score(scan_result)
        self.assertEqual(base_score, 7.1)

    def test_base_score_with_identical_scores(self):
        """
        Tests correct handling of identical highest scores.
        """
        cve_findings = [
            CveFinding(id="cve1", cve_id="CVE-2025-005", description="A finding", score=9.0, location="server-e"),
        ]
        cwe_findings = [
            CweFinding(id="cwe1", cwe=self.cwe_info_sqli, description="Another finding", score=9.0, location="api.py"),
        ]
        scan_result = ScanResult(company_id="c5", cve_findings=cve_findings, cwe_findings=cwe_findings)
        base_score = determine_base_score(scan_result)
        self.assertEqual(base_score, 9.0)


if __name__ == '__main__':
    unittest.main()