import json
import os
import pathlib
import subprocess
import sys
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"
CLIPATH = pathlib.Path(os.path.dirname(__file__)).parent / "badkeys-cli"


class TestMultiblock(unittest.TestCase):
    def test_mixed_bundle(self):
        indata = pathlib.Path(f"{TDPATH}multiblock/mixed.pem").read_text()
        rl = badkeys.detectandcheckall(indata, checks=["fermat"])
        self.assertEqual(len(rl), 6)
        self.assertEqual([r["block"] for r in rl], [0, 1, 2, 3, 4, 5])
        # ok public key, vulnerable certificate/csr/public key, private key
        for blockno in range(5):
            self.assertEqual(rl[blockno]["type"], "rsa")
        for blockno in (1, 2, 3):
            self.assertIn("fermat", rl[blockno]["results"])
        self.assertEqual(rl[0]["results"], {})
        self.assertEqual(rl[4]["results"], {})
        # defect block
        self.assertEqual(rl[5]["type"], "unparseable")

    def test_truncated_block(self):
        indata = pathlib.Path(f"{TDPATH}multiblock/truncated.pem").read_text()
        rl = badkeys.detectandcheckall(indata, checks=["fermat"])
        self.assertEqual(len(rl), 2)
        self.assertEqual(rl[0]["type"], "rsa")
        self.assertEqual(rl[1]["type"], "unparseable")

    def test_single_block(self):
        indata = pathlib.Path(f"{TDPATH}rsa-ok.key").read_text()
        rl = badkeys.detectandcheckall(indata, checks=["fermat"])
        self.assertEqual(len(rl), 1)
        self.assertEqual(rl[0]["block"], 0)
        self.assertEqual(rl[0]["type"], "rsa")
        self.assertEqual(rl[0]["results"], {})

    def test_first_item_interface_unchanged(self):
        indata = pathlib.Path(f"{TDPATH}rsa-fermat.crt").read_text()
        r = badkeys.detectandcheck(indata, checks=["fermat"])
        self.assertIn("fermat", r["results"])
        self.assertNotIn("block", r)
        rl = badkeys.detectandcheckall(indata, checks=["fermat"])
        self.assertEqual(len(rl), 1)
        self.assertEqual({k: v for k, v in rl[0].items() if k != "block"}, r)

    def test_cli_multiblock(self):
        fn = f"{TDPATH}multiblock/mixed.pem"
        p = subprocess.run([sys.executable, CLIPATH, "-c", "fermat", fn],
                           capture_output=True, text=True)
        # bit 2: unparseable block warning, bit 4: vulnerabilities found
        self.assertEqual(p.returncode, 6)
        self.assertEqual(p.stdout.count("fermat vulnerability"), 3)
        self.assertIn(f"{fn}[1]", p.stdout)
        self.assertIn(f"{fn}[3]", p.stdout)
        self.assertIn(f"Unparseable input, {fn}[5]", p.stderr)

    def test_cli_multiblock_json(self):
        fn = f"{TDPATH}multiblock/mixed.pem"
        p = subprocess.run([sys.executable, CLIPATH, "-j", "-c", "fermat", fn],
                           capture_output=True, text=True)
        lines = p.stdout.splitlines()
        self.assertEqual(len(lines), 4)
        for blockno, line in zip([1, 2, 3, 5], lines, strict=True):
            j = json.loads(line)
            self.assertEqual(j["block"], blockno)
            self.assertEqual(j["where"], f"{fn}[{blockno}]")
        self.assertEqual(json.loads(lines[3])["type"], "unparseable")

    def test_cli_single_block_unchanged(self):
        fn = f"{TDPATH}rsa-fermat.crt"
        p = subprocess.run([sys.executable, CLIPATH, "-c", "fermat", fn],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 4)
        self.assertIn(f"fermat vulnerability, rsa[2048], {fn}", p.stdout)
        p = subprocess.run([sys.executable, CLIPATH, "-j", "-c", "fermat", fn],
                           capture_output=True, text=True)
        lines = p.stdout.splitlines()
        self.assertEqual(len(lines), 1)
        j = json.loads(lines[0])
        self.assertEqual(j["where"], fn)
        self.assertNotIn("block", j)


if __name__ == "__main__":
    unittest.main()
