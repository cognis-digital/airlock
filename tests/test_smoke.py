"""Smoke tests for airlock. Standard library only, no network."""

import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airlock import TOOL_NAME, TOOL_VERSION, create_bundle, verify_bundle
from airlock.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_DIR = os.path.join(REPO_ROOT, "demos", "01-basic")
DEMO_YAML = os.path.join(DEMO_DIR, "airlock.yaml")
DEMO_JSON = os.path.join(DEMO_DIR, "airlock.json")


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "airlock")
        self.assertTrue(TOOL_VERSION)


class TestCreateInspectVerify(unittest.TestCase):
    def test_create_from_yaml_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bundle.tar")
            payload = create_bundle(DEMO_YAML, out, pull=False)
            self.assertTrue(os.path.isfile(out))
            self.assertEqual(payload["name"], "hello-edge")
            # 2 images + 1 chart + 2 manifests + 2 files = 7 artifacts.
            self.assertEqual(payload["artifact_count"], 7)
            self.assertTrue(payload["merkle_root"])
            res = verify_bundle(out)
            self.assertTrue(res["ok"], res["problems"])
            self.assertEqual(res["checked"], 7)

    def test_create_from_json_equivalent(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bundle.tar")
            payload = create_bundle(DEMO_JSON, out, pull=False)
            self.assertEqual(payload["artifact_count"], 7)

    def test_bundle_has_control_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bundle.tar")
            create_bundle(DEMO_YAML, out, pull=False)
            with tarfile.open(out) as tar:
                names = set(tar.getnames())
            self.assertIn("bundle.json", names)
            self.assertIn("checksums.txt", names)
            self.assertIn("attestation.json", names)

    def test_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bundle.tar")
            create_bundle(DEMO_YAML, out, pull=False)
            tampered = _tamper_one_artifact(out, tmp)
            res = verify_bundle(tampered)
            self.assertFalse(res["ok"])
            self.assertTrue(any("mismatch" in p for p in res["problems"]))


class TestCli(unittest.TestCase):
    def test_full_cli_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bundle.tar")
            self.assertEqual(main(["create", DEMO_YAML, "-o", out]), 0)
            self.assertEqual(main(["inspect", out]), 0)
            self.assertEqual(main(["verify", out]), 0)
            self.assertEqual(main(["deploy", out, "--dry-run"]), 0)

    def test_deploy_dry_run_prints_commands(self):
        proc = subprocess.run(
            [sys.executable, "-m", "airlock", "create", DEMO_YAML,
             "-o", os.path.join(tempfile.gettempdir(), "airlock_smoke.tar")],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        bundle = os.path.join(tempfile.gettempdir(), "airlock_smoke.tar")
        proc = subprocess.run(
            [sys.executable, "-m", "airlock", "deploy", bundle, "--dry-run"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("docker", proc.stdout)
        self.assertIn("kubectl apply", proc.stdout)
        self.assertIn("helm install", proc.stdout)

    def test_verify_json_returncode(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "bundle.tar")
            main(["create", DEMO_YAML, "-o", out])
            proc = subprocess.run(
                [sys.executable, "-m", "airlock", "verify", out, "--format", "json"],
                cwd=REPO_ROOT, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertTrue(data["ok"])

    def test_missing_bundle_exits_2(self):
        self.assertEqual(main(["inspect", "/no/such/bundle.tar"]), 2)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)


def _tamper_one_artifact(bundle_path, tmp):
    """Rewrite the archive flipping the bytes of the first artifact file."""
    new_path = os.path.join(tmp, "tampered.tar")
    with tarfile.open(bundle_path, "r") as src, tarfile.open(new_path, "w") as dst:
        for member in src.getmembers():
            data = src.extractfile(member).read() if member.isfile() else b""
            if member.name.startswith("artifacts/") and member.name.endswith(".env"):
                data = data + b"\n# tampered\n"
                member.size = len(data)
            import io
            dst.addfile(member, io.BytesIO(data))
    return new_path


if __name__ == "__main__":
    unittest.main()
