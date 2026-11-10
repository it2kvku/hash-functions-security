import tempfile
import unittest
from pathlib import Path

from src import password_auth


class PasswordTest(unittest.TestCase):
    def test_format_and_verify(self):
        stored = password_auth.hash_password("s3cret!")
        parts = stored.split("$")
        self.assertEqual(parts[0], "pbkdf2_sha256")
        self.assertEqual(parts[1], str(password_auth.ITERATIONS))
        self.assertEqual(len(bytes.fromhex(parts[2])), 16)  # salt 16 byte
        self.assertTrue(password_auth.verify_password("s3cret!", stored))
        self.assertFalse(password_auth.verify_password("wrong", stored))

    def test_unique_salt_per_user(self):
        a = password_auth.hash_password("same-password")
        b = password_auth.hash_password("same-password")
        self.assertNotEqual(a, b)

    def test_verify_rejects_malformed(self):
        self.assertFalse(password_auth.verify_password("x", "not-a-valid-record"))
        self.assertFalse(password_auth.verify_password("x", ""))

    def test_store_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = password_auth.UserStore(Path(tmp) / "users.json")
            store.register("alice", "pw123")
            self.assertTrue(store.login("alice", "pw123"))
            self.assertFalse(store.login("alice", "bad"))
            with self.assertRaises(ValueError):
                store.register("alice", "other")  # trung ten
            with self.assertRaises(ValueError):
                store.register("", "pw")  # rong

    def test_md5_vector(self):
        self.assertEqual(password_auth.insecure_md5("abc"),
                         "900150983cd24fb0d6963f7d28e17f72")


if __name__ == "__main__":
    unittest.main()
