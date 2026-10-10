"""Tests for India Digital Rights & Cyber Law Knowledge Center."""
import unittest

from legal_knowledge.storage import LegalKnowledgeStorage


class TestLegalKnowledgeCenter(unittest.TestCase):
    def setUp(self):
        self.storage = LegalKnowledgeStorage()

    def test_all_instruments_have_verified_sources(self):
        instruments = self.storage.get_all_instruments()
        self.assertGreaterEqual(len(instruments), 5)
        for inst in instruments:
            self.assertTrue(inst.official_source_url.startswith("http"))
            self.assertIsNotNone(inst.last_verified_at)
            self.assertGreaterEqual(len(inst.provisions), 1)
            self.assertGreaterEqual(len(inst.citizen_remedies), 1)

    def test_dpdp_commencement_status_explicit(self):
        dpdp = self.storage.get_instrument("dpdp-act-2023")
        self.assertIsNotNone(dpdp)
        self.assertEqual(dpdp.commencement_status, "phased_commencement")
        self.assertIn("2025", dpdp.commencement_note)

    def test_constitution_puttaswamy_privacy_citation(self):
        const_inst = self.storage.get_instrument("constitution-india")
        self.assertIsNotNone(const_inst)
        art21 = next((p for p in const_inst.provisions if p["section_or_article"] == "Article 21"), None)
        self.assertIsNotNone(art21)
        self.assertIn("Puttaswamy", art21["plain_explanation"])

    def test_scenarios_and_reporting_links(self):
        scenarios = self.storage.get_all_scenarios()
        self.assertGreaterEqual(len(scenarios), 3)
        for sc in scenarios:
            self.assertTrue(sc.portal_url.startswith("http"))
            self.assertGreaterEqual(len(sc.potentially_applicable_laws), 1)
            self.assertGreaterEqual(len(sc.immediate_citizen_actions), 2)

    def test_cross_cutting_search(self):
        results = self.storage.search_all("UPI")
        self.assertGreaterEqual(len(results["scenarios"]), 1)
        self.assertGreaterEqual(len(results["instruments"]), 1)


if __name__ == "__main__":
    unittest.main()
