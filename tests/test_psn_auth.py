"""Basic security primitive tests for PSN account routes."""
import unittest
from psn_auth import hash_password, verify_password, otp_digest, token_digest


class AuthPrimitiveTests(unittest.TestCase):
    def test_password_hash_is_salted_and_verifiable(self):
        first = hash_password("sample-strong-password")
        second = hash_password("sample-strong-password")
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password("sample-strong-password", first))
        self.assertFalse(verify_password("incorrect-password", first))

    def test_otp_digest_is_bound_to_mobile_and_code(self):
        a = otp_digest("+919876543210", "123456")
        self.assertEqual(a, otp_digest("+919876543210", "123456"))
        self.assertNotEqual(a, otp_digest("+919876543211", "123456"))
        self.assertNotEqual(a, otp_digest("+919876543210", "123457"))

    def test_session_tokens_are_hashed(self):
        self.assertNotEqual(token_digest("session-token"), "session-token")
        self.assertEqual(token_digest("session-token"), token_digest("session-token"))


if __name__ == "__main__":
    unittest.main()
