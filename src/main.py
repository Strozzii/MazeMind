"""
The main entry point for the MazeMind application.

This script demonstrates the full end-to-end workflow:
1. Simulates a vulnerability scan result.
2. Calls the THESEUS module to calculate a base score.
3. Calls the ARIADNE module to generate the final, model-adjusted score.
4. Prints the final result to the console.
"""
from src.common.models import ScanResult, CveFinding, CweFinding, CweInfo
from src.theseus.core import determine_base_score
from src.ariadne.core import generate_final_score


def main():
    """Main function to run the CRS calculation process."""
    print("--- Starting MazeMind CyberRiskScore Calculation ---")

    # 1. Simulate a new vulnerability scan result for a company.
    #    In a real application, this would come from a scanner.
    print("\n[Step 1] Loading new scan result for 'SecureSoft Inc.'...")
    scan_result = ScanResult(
        company_id="SecureSoft Inc.",
        cve_findings=[
            CveFinding(id="vuln-001", cve_id="CVE-2025-001", score=9.8, description="Critical RCE", location="auth-service"),
            CveFinding(id="vuln-002", cve_id="CVE-2025-002", score=7.5, description="High risk", location="api-gateway"),
        ],
        cwe_findings=[
            CweFinding(id="vuln-003", cwe=CweInfo(id="CWE-79", name="XSS"), score=6.1, description="XSS in dashboard", location="webapp"),
            CweFinding(id="vuln-004", cwe=CweInfo(id="CWE-306", name="Missing Auth"), score=5.4, description="Auth missing", location="internal-api"),
            CweFinding(id="vuln-005", cwe=CweInfo(id="CWE-200", name="Info Exposure"), score=3.1, description="Info leak", location="web-server"),
        ]
    )

    # 2. Call THESEUS to determine the base score.
    print("[Step 2] Calculating base score with THESEUS...")
    base_score = determine_base_score(scan_result)
    print(f"   -> Base Score: {base_score:.2f}")

    # 3. Call ARIADNE to get the final, model-adjusted score.
    print("[Step 3] Adjusting score with ARIADNE's ML model...")
    final_crs_object = generate_final_score(scan_result, base_score)
    print("   -> ARIADNE calculation complete.")

    # 4. Print the final results.
    print("\n--- ✅ Final CyberRiskScore ---")
    print(f"Company:          {final_crs_object.company_id}")
    print(f"Base Score:       {final_crs_object.base_score:.2f}")
    print(f"Key Risk Factor:  {final_crs_object.key_risk_factors[0]}")
    print("------------------------------------")
    print(f"Final CRS:        {final_crs_object.crs_score:.2f} / 10.0")
    print("------------------------------------")


if __name__ == "__main__":
    # To run the project, execute this command from the root directory:
    # python -m src.main
    main()