import secrets
import unittest

from src import hmac_channel


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
