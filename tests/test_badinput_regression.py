# SPDX-License-Identifier: MIT

import json
import os
import pathlib
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"
RSA_CHECKS = [name for name, spec in badkeys.allchecks.items() if spec["type"] == "rsa"]


class TestBadInputRegression(unittest.TestCase):
    def test_malformed_jwk_is_unparseable(self):
        malformed = [
            123,
            ["not", "a", "jwk"],
            {"kty": "RSA"},
            {"kty": "RSA", "n": {}, "e": {}},
            {"kty": "RSA", "n": 123, "e": 65537},
            {"kty": "RSA", "n": " ", "e": "AQAB"},
            {"kty": "RSA", "n": "AA", "e": "AQAB"},
            {"kty": "RSA", "n": "AAE", "e": " "},
            {"kty": "EC", "x": {}, "y": {}, "crv": "P-256"},
        ]
        for jkey in malformed:
            with self.subTest(jkey=jkey):
                ret = badkeys.checkjwk(jkey, checks=RSA_CHECKS)
                self.assertEqual(ret["type"], "unparseable")
                self.assertEqual(ret["results"], {})

    def test_invalid_rsa_moduli_do_not_raise(self):
        for n in (0, -1):
            with self.subTest(n=n):
                ret = badkeys.checkrsa(n, e=65537, checks=RSA_CHECKS)
                self.assertIsInstance(ret, dict)

    def test_valid_rsa_jwk_still_parses(self):
        jkey = json.loads(pathlib.Path(f"{TDPATH}jwk-rsa-ok.json").read_text())
        ret = badkeys.checkjwk(jkey, checks=["roca", "pattern", "sharedprimes", "fermat"])
        self.assertEqual(ret["type"], "rsa")
        self.assertEqual(ret["bits"], 2048)
        self.assertFalse(ret["results"])


if __name__ == "__main__":
    unittest.main()
