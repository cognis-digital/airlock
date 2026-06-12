"""Feature tests for airlock — extract (safe + verified), diff, CLI."""

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airlock import create_bundle, diff_bundles, extract_bundle
from airlock.core import AirlockError
from airlock.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_YAML = os.path.join(REPO_ROOT, "demos", "01-basic", "airlock.yaml")


class TestExtract(unittest.TestCase):
    def test_extract_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = os.path.join(tmp, "b.tar")
            create_bundle(DEMO_YAML, bundle, pull=False)
            dest = os.path.join(tmp, "out")
            res = extract_bundle(bundle, dest)
            self.assertTrue(res["verified"])
            self.assertGreater(res["extracted"], 0)
            self.assertTrue(os.path.isfile(os.path.join(dest, "bundle.json")))

    def test_extract_refuses_tampered(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = os.path.join(tmp, "b.tar")
            create_bundle(DEMO_YAML, bundle, pull=False)
            # Tamper a packed artifact.
            tampered = os.path.join(tmp, "t.tar")
            with tarfile.open(bundle) as src, tarfile.open(tampered, "w") as dst:
                for m in src.getmembers():
                    data = src.extractfile(m).read() if m.isfile() else b""
                    if m.name.endswith(".env"):
                        data += b"\n# evil\n"
                        m.size = len(data)
                    dst.addfile(m, io.BytesIO(data))
            with self.assertRaises(AirlockError):
                extract_bundle(tampered, os.path.join(tmp, "out"))

    def test_extract_no_verify_allows_tampered(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = os.path.join(tmp, "b.tar")
            create_bundle(DEMO_YAML, bundle, pull=False)
            res = extract_bundle(bundle, os.path.join(tmp, "out"), verify=False)
            self.assertFalse(res["verified"])


class TestDiff(unittest.TestCase):
    def test_identical_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            b1 = os.path.join(tmp, "b1.tar")
            b2 = os.path.join(tmp, "b2.tar")
            create_bundle(DEMO_YAML, b1, pull=False)
            create_bundle(DEMO_YAML, b2, pull=False)
            d = diff_bundles(b1, b2)
            self.assertTrue(d["identical"])
            self.assertEqual(d["added"], [])
            self.assertEqual(d["changed"], [])

    def test_changed_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Build one bundle, then a second from a manifest with an extra file.
            b1 = os.path.join(tmp, "b1.tar")
            create_bundle(DEMO_YAML, b1, pull=False)
            # Make a minimal second manifest with one different file.
            extra = os.path.join(tmp, "note.txt")
            with open(extra, "w") as fh:
                fh.write("hello")
            m2 = os.path.join(tmp, "airlock2.yaml")
            with open(m2, "w") as fh:
                fh.write("name: t\nversion: 1.0.0\nfiles:\n  - note.txt\n")
            b2 = os.path.join(tmp, "b2.tar")
            create_bundle(m2, b2, pull=False)
            d = diff_bundles(b1, b2)
            self.assertFalse(d["identical"])
            self.assertIn("note.txt", d["added"])


class TestCliFeatures(unittest.TestCase):
    def test_extract_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = os.path.join(tmp, "b.tar")
            self.assertEqual(main(["create", DEMO_YAML, "-o", bundle]), 0)
            self.assertEqual(main(["extract", bundle, os.path.join(tmp, "out")]), 0)

    def test_diff_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            b1 = os.path.join(tmp, "b1.tar")
            b2 = os.path.join(tmp, "b2.tar")
            main(["create", DEMO_YAML, "-o", b1])
            main(["create", DEMO_YAML, "-o", b2])
            self.assertEqual(main(["diff", b1, b2]), 0)
            self.assertEqual(main(["diff", b1, b2, "--format", "json"]), 0)


if __name__ == "__main__":
    unittest.main()
