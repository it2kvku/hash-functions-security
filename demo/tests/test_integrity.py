import tempfile
import unittest
from pathlib import Path

from src import integrity


class IntegrityTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "a.txt").write_text("hello", encoding="utf-8")
        (self.root / "b.txt").write_text("world", encoding="utf-8")
        self.manifest = self.root / "integrity.manifest.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_baseline_then_clean_verify(self):
        integrity.save_baseline(self.root, self.manifest)
        report = integrity.verify(self.root, self.manifest)
        self.assertEqual(len(report["ok"]), 2)
        self.assertEqual(report["modified"], [])
        self.assertEqual(report["added"], [])

    def test_tamper_detected(self):
        integrity.save_baseline(self.root, self.manifest)
        (self.root / "a.txt").write_text("hacked", encoding="utf-8")
        report = integrity.verify(self.root, self.manifest)
        self.assertIn("a.txt", report["modified"])

    def test_delete_and_add_detected(self):
        integrity.save_baseline(self.root, self.manifest)
        (self.root / "b.txt").unlink()
        (self.root / "c.txt").write_text("new", encoding="utf-8")
        report = integrity.verify(self.root, self.manifest)
        self.assertIn("b.txt", report["deleted"])
        self.assertIn("c.txt", report["added"])

    def test_manifest_excluded_from_scan(self):
        integrity.save_baseline(self.root, self.manifest)
        report = integrity.verify(self.root, self.manifest)
        self.assertNotIn("integrity.manifest.json", report["added"])


if __name__ == "__main__":
    unittest.main()
