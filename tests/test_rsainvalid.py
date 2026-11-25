# SPDX-License-Identifier: MIT
# (c) Hanno Böck

import os
import pathlib
import unittest

import badkeys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestRSAInvalid(unittest.TestCase):
    def test_rsainvalid(self):
        key = pathlib.Path(f"{TDPATH}rsa-e1.key").read_text()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertEqual(r["type"], "unparseable")

        key = pathlib.Path(f"{TDPATH}rsa-e-larger-n.key").read_text()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertEqual(r["type"], "unparseable")

        key = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        r = badkeys.checkpubkey(key, checks=["rsainvalid"])
        self.assertFalse(r["results"])

    def test_rsa_invalid_private_factors(self):
        key = pathlib.Path(f"{TDPATH}rsa-invalid-factors.key").read_text()
        r = badkeys.checkprivkey(key, checks=["rsainvalid"])
        self.assertEqual(r["type"], "unparseable")
        self.assertFalse(r["results"])

    def test_rsa_equal_private_factors(self):
        key = pathlib.Path(f"{TDPATH}rsa-equal-factors.key").read_text()
        r = badkeys.checkprivkey(key, checks=["rsainvalid"])
        self.assertEqual(r["type"], "unparseable")
        self.assertFalse(r["results"])

    def test_rsa_valid_private_factors(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
        r = badkeys.checkprivkey(pem, checks=["rsainvalid"])
        self.assertEqual(r["type"], "rsa")
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
