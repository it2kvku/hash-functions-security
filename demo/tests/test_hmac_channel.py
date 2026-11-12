import secrets
import unittest

from src import hmac_channel

# Secret chuan cua test vectors RFC 4226 / RFC 6238
RFC_SECRET = b"12345678901234567890"


class OtpTest(unittest.TestCase):
    def test_hotp_rfc4226_appendix_d(self):
        # Du lieu kiem cham chuan trong RFC 4226, phu luc D
        self.assertEqual(hmac_channel.hotp(RFC_SECRET, 0), "755224")
        self.assertEqual(hmac_channel.hotp(RFC_SECRET, 1), "287082")
        self.assertEqual(hmac_channel.hotp(RFC_SECRET, 2), "359152")
        self.assertEqual(hmac_channel.hotp(RFC_SECRET, 9), "520489")

    def test_totp_rfc6238_vectors(self):
        # Du lieu kiem cham chuan trong RFC 6238 (SHA-1, 8 chu so)
        self.assertEqual(hmac_channel.totp(RFC_SECRET, now=59, digits=8), "94287082")
        self.assertEqual(hmac_channel.totp(RFC_SECRET, now=1111111109, digits=8), "07081804")
        self.assertEqual(hmac_channel.totp(RFC_SECRET, now=1234567890, digits=8), "89005924")
        self.assertEqual(hmac_channel.totp(RFC_SECRET, now=2000000000, digits=8), "69279037")

    def test_totp_same_window_same_code(self):
        # Cua so [60, 90): 60 va 89 cung counter = 2
        a = hmac_channel.totp(RFC_SECRET, now=60, digits=8)
        b = hmac_channel.totp(RFC_SECRET, now=89, digits=8)
        self.assertEqual(a, b)

    def test_totp_remaining_in_range(self):
        self.assertTrue(1 <= hmac_channel.totp_remaining(now=61) <= 30)
        self.assertEqual(hmac_channel.totp_remaining(now=60), 30)


class HmacTest(unittest.TestCase):
    def test_honest_exchange_verifies(self):
        key = secrets.token_bytes(32)
        tag = hmac_channel.sign(key, "msg")
        self.assertTrue(hmac_channel.verify(key, "msg", tag))

    def test_tampered_message_fails(self):
        key = secrets.token_bytes(32)
        tag = hmac_channel.sign(key, "pay 100")
        self.assertFalse(hmac_channel.verify(key, "pay 999", tag))

    def test_wrong_key_fails(self):
        tag = hmac_channel.sign(b"k1", "msg")
        self.assertFalse(hmac_channel.verify(b"k2", "msg", tag))

    def test_demo_scenarios_shape(self):
        rows = hmac_channel.exchange_demo()
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[0]["verified"])
        self.assertFalse(rows[1]["verified"])
        self.assertFalse(rows[2]["verified"])

    def test_tamper_story_consistent(self):
        # Cung cau chuyen voi integrity.tamper(): 12tr -> 98tr
        self.assertIn("98.000.000", hmac_channel.TAMPERED)
        self.assertIn("12.000.000", hmac_channel.MESSAGE)


if __name__ == "__main__":
    unittest.main()
