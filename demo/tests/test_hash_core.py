import unittest

from src import hash_core


class HashCoreTest(unittest.TestCase):
    def test_sha256_known_vector(self):
        # Standard test vector: sha256("abc")
        self.assertEqual(
            hash_core.hash_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_md5_known_vector(self):
        # Standard test vector: md5("abc")
        self.assertEqual(hash_core.hash_text("abc", "md5"),
                         "900150983cd24fb0d6963f7d28e17f72")

    def test_deterministic(self):
        self.assertEqual(hash_core.hash_text("abc"), hash_core.hash_text("abc"))

    def test_avalanche_changes_digest(self):
        r = hash_core.avalanche("Bao mat he thong thong tin")
        self.assertNotEqual(r["original"], r["variant"])

    def test_compare_all_algorithms(self):
        rows = hash_core.compare("abc")
        self.assertEqual(len(rows), len(hash_core.ALGORITHMS))
        for row in rows:
            self.assertTrue(len(row["digest"]) >= 32)


if __name__ == "__main__":
    unittest.main()
