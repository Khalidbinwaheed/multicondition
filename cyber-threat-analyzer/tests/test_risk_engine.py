import unittest
from src.risk_engine import calculate_risk_score, classify_risk, calculate_risk_factors

class TestRiskEngine(unittest.TestCase):

    def test_classify_risk_boundaries(self):
        # Test exact boundaries and surrounding values
        
        # >= 90
        self.assertEqual(classify_risk(100)["severity"], "CRITICAL")
        self.assertEqual(classify_risk(90)["severity"], "CRITICAL")
        self.assertEqual(classify_risk(89)["severity"], "HIGH")
        
        # >= 70
        self.assertEqual(classify_risk(70)["severity"], "HIGH")
        self.assertEqual(classify_risk(69)["severity"], "MEDIUM")
        
        # >= 40
        self.assertEqual(classify_risk(40)["severity"], "MEDIUM")
        self.assertEqual(classify_risk(39)["severity"], "LOW")
        
        # >= 20
        self.assertEqual(classify_risk(20)["severity"], "LOW")
        self.assertEqual(classify_risk(19)["severity"], "INFORMATIONAL")
        
        # 0
        self.assertEqual(classify_risk(0)["severity"], "INFORMATIONAL")

    def test_calculate_risk_score_max(self):
        score = calculate_risk_score(
            severity="Critical",
            exploitability="Easy",
            exposure="Internet-facing",
            confidence="High",
            frequency="Repeated"
        )
        self.assertEqual(score, 100)
        
    def test_calculate_risk_factors(self):
        breakdown = calculate_risk_factors(
            severity="Critical",
            exploitability="Easy",
            exposure="Internet-facing",
            confidence="High",
            frequency="Repeated"
        )
        self.assertEqual(breakdown["Vulnerability Severity"], 30)
        self.assertEqual(breakdown["Exploitability"], 20)
        self.assertEqual(breakdown["Asset Exposure"], 20)
        self.assertEqual(breakdown["Detection Confidence"], 20)
        self.assertEqual(breakdown["Event Frequency"], 10)
        self.assertEqual(sum(breakdown.values()), 100)

    def test_calculate_risk_score_min(self):
        score = calculate_risk_score(
            severity="Informational",
            exploitability="Difficult",
            exposure="Isolated",
            confidence="Low",
            frequency="Single Event"
        )
        self.assertEqual(score, 0)

if __name__ == '__main__':
    unittest.main()
