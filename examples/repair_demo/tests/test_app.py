"""Behavior checks that pass both before and after the candidate patch."""

import os
import unittest


os.environ["PASSWORD"] = "synthetic_demo_password_only"
import app  # noqa: E402


class AppTests(unittest.TestCase):
    def test_digest_is_hex(self):
        result = app.digest(b"demo")
        self.assertIn(len(result), (32, 64))
        self.assertTrue(all(ch in "0123456789abcdef" for ch in result))

    def test_nonce_shape(self):
        result = app.issue_nonce()
        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 12)

    def test_auth(self):
        self.assertTrue(app.authenticate("synthetic_demo_password_only"))
        self.assertFalse(app.authenticate("wrong"))
