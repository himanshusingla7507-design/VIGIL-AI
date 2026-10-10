"""Tests for Cyber Scam Case Broadcast module."""
import json
import os
import tempfile
import unittest

from scam_broadcast.models import ScamCaseBroadcast
from scam_broadcast.storage import ScamCaseStorage


class TestScamCaseBroadcast(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
        self.temp_db.close()
        self.storage = ScamCaseStorage(db_path=self.temp_db.name)

    def tearDown(self):
        try:
            os.remove(self.temp_db.name)
        except OSError:
            pass

    def test_seeded_cases_exist_and_valid(self):
        cases, total = self.storage.query_cases(limit=10)
        self.assertGreaterEqual(total, 3)
        self.assertTrue(any(c.scam_type == "digital_arrest" for c in cases))
        self.assertTrue(any(c.scam_type == "upi_qr_fraud" for c in cases))

    def test_get_case_by_slug_and_id(self):
        case_by_slug = self.storage.get_case("digital-arrest-law-enforcement-impersonation")
        self.assertIsNotNone(case_by_slug)
        self.assertEqual(case_by_slug.id, "case-digital-arrest-01")
        self.assertIn("Digital Arrest", case_by_slug.title)
        self.assertGreaterEqual(len(case_by_slug.attack_chain), 3)
        self.assertGreaterEqual(len(case_by_slug.warning_signs), 2)
        self.assertGreaterEqual(len(case_by_slug.legal_provisions), 1)

    def test_filter_cases_by_type_and_search(self):
        cases, total = self.storage.query_cases(scam_type="upi_qr_fraud")
        self.assertGreaterEqual(total, 1)
        self.assertEqual(cases[0].scam_type, "upi_qr_fraud")

        search_cases, search_total = self.storage.query_cases(search="Telegram")
        self.assertGreaterEqual(search_total, 1)
        self.assertIn("job", search_cases[0].scam_type)

    def test_scam_stats(self):
        stats = self.storage.get_scam_stats()
        self.assertIn("total_cases", stats)
        self.assertIn("by_type", stats)
        self.assertIn("by_severity", stats)
        self.assertGreaterEqual(stats["total_cases"], 3)


if __name__ == "__main__":
    unittest.main()
