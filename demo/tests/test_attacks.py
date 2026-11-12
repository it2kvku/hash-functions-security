import hashlib
import struct
import unittest

from src import attacks


class BirthdayTest(unittest.TestCase):
    def test_finds_small_prefix_collision(self):
        r = attacks.truncated_collision(bits=12, max_trials=100_000)
        self.assertTrue(r["found"])
        self.assertEqual(r["bits"], 12)
        self.assertLessEqual(r["trials"], 100_000)

    def test_inputs_differ(self):
        r = attacks.truncated_collision(bits=12, max_trials=100_000)
        self.assertNotEqual(r["a"], r["b"])


class LengthExtensionTest(unittest.TestCase):
    def test_md5_core_matches_hashlib_on_padded_input(self):
        # Tu tag cua thong diep rong (= IV cua MD5) ke tiep bam X
        # phai bang hashlib.md5(glue + X) — kiem chung loi MD5 tu viet.
        tag0 = hashlib.md5(b"").hexdigest()
        suffix = b"abc" * 40  # nhieu khoi
        forged, appended = attacks.md5_length_extend(tag0, 0, suffix)
        self.assertTrue(appended.endswith(suffix))
        self.assertEqual(forged, hashlib.md5(appended).hexdigest())

    def test_length_extension_forges_valid_tag(self):
        key = b"super-secret-key"
        msg = b"amount=100; admin=false"
        tag = hashlib.md5(key + msg).hexdigest()
        suffix = b"; admin=true"
        forged, appended = attacks.md5_length_extend(tag, len(key) + len(msg), suffix)
        self.assertEqual(forged, hashlib.md5(key + msg + appended).hexdigest())
        self.assertTrue(appended.endswith(suffix))

    def test_glue_padding_structure(self):
        # glue cho do dai L: 0x80 + zeros + 8-byte LE bit-length cua L
        _, appended = attacks.md5_length_extend(hashlib.md5(b"").hexdigest(), 5, b"x")
        glue = appended[:len(appended) - 1]
        self.assertEqual(glue[0], 0x80)
        self.assertEqual(glue[-8:], struct.pack("<Q", 5 * 8))
        self.assertEqual(len(glue), 1 + ((55 - 5) % 64) + 8)

    def test_demo_forge_valid(self):
        r = attacks.length_extension_demo()
        self.assertTrue(r["forge_valid"])
        self.assertIn("admin=true", r["forged_message_display"])


if __name__ == "__main__":
    unittest.main()
