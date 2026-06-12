"""Deep tests for airlock — parser, hashing, layout, deploy plan, MCP, AI hook."""

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airlock import (
    create_bundle,
    draft_manifest,
    inspect_bundle,
    merkle_root,
    parse_yaml_subset,
    plan_deploy,
    sha256_bytes,
    verify_bundle,
)
from airlock.core import load_manifest, resolve_artifacts, AirlockError
from airlock import mcp_server

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_DIR = os.path.join(REPO_ROOT, "demos", "01-basic")
DEMO_YAML = os.path.join(DEMO_DIR, "airlock.yaml")


class TestYamlSubset(unittest.TestCase):
    def test_scalars_and_types(self):
        data = parse_yaml_subset(
            "name: app\nversion: 2\nratio: 1.5\nenabled: true\nempty: null\n")
        self.assertEqual(data["name"], "app")
        self.assertEqual(data["version"], 2)
        self.assertEqual(data["ratio"], 1.5)
        self.assertIs(data["enabled"], True)
        self.assertIsNone(data["empty"])

    def test_quoted_string_with_colon(self):
        data = parse_yaml_subset('title: "a: b"\n')
        self.assertEqual(data["title"], "a: b")

    def test_comments_and_blank_lines(self):
        data = parse_yaml_subset("# header\nname: x   # trailing\n\nv: 1\n")
        self.assertEqual(data["name"], "x")
        self.assertEqual(data["v"], 1)

    def test_block_list_of_scalars(self):
        data = parse_yaml_subset("images:\n  - a:1\n  - b:2\n")
        self.assertEqual(data["images"], ["a:1", "b:2"])

    def test_list_of_mappings(self):
        text = ("charts:\n"
                "  - name: redis\n"
                "    repo: https://example.com\n"
                "    version: 1.0.0\n")
        data = parse_yaml_subset(text)
        self.assertEqual(len(data["charts"]), 1)
        self.assertEqual(data["charts"][0]["name"], "redis")
        self.assertEqual(data["charts"][0]["repo"], "https://example.com")
        self.assertEqual(data["charts"][0]["version"], "1.0.0")

    def test_matches_demo_manifest_shape(self):
        data = load_manifest(DEMO_YAML)
        self.assertEqual(data["name"], "hello-edge")
        self.assertEqual(len(data["images"]), 2)
        self.assertEqual(len(data["charts"]), 1)
        self.assertEqual(data["charts"][0]["release"], "cache")


class TestHashing(unittest.TestCase):
    def test_merkle_root_stable_and_sensitive(self):
        a = merkle_root([sha256_bytes(b"x"), sha256_bytes(b"y")])
        b = merkle_root([sha256_bytes(b"y"), sha256_bytes(b"x")])  # order independent
        self.assertEqual(a, b)
        c = merkle_root([sha256_bytes(b"x"), sha256_bytes(b"z")])
        self.assertNotEqual(a, c)

    def test_empty_merkle_root(self):
        self.assertEqual(merkle_root([]), sha256_bytes(b""))


class TestResolve(unittest.TestCase):
    def test_missing_manifest_file_raises(self):
        m = {"manifests": ["nope/missing.yaml"]}
        with self.assertRaises(AirlockError):
            resolve_artifacts(m, DEMO_DIR)

    def test_image_string_and_object_forms(self):
        m = {"images": ["nginx:1", {"ref": "redis:7"}]}
        arts = resolve_artifacts(m, DEMO_DIR)
        self.assertEqual([a.name for a in arts], ["nginx:1", "redis:7"])


class TestBundleLayout(unittest.TestCase):
    def test_layout_and_intent_recording(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "b.tar")
            payload = create_bundle(DEMO_YAML, out, pull=False)
            kinds = {a["kind"] for a in payload["artifacts"]}
            self.assertEqual(kinds, {"images", "charts", "manifests", "files"})
            # Offline => images/charts recorded as intent, files/manifests packed.
            statuses = {a["kind"]: a["status"] for a in payload["artifacts"]}
            img = [a for a in payload["artifacts"] if a["kind"] == "images"][0]
            self.assertEqual(img["status"], "recorded")
            fil = [a for a in payload["artifacts"] if a["kind"] == "files"][0]
            self.assertEqual(fil["status"], "packed")
            with tarfile.open(out) as tar:
                names = tar.getnames()
            self.assertTrue(any(n.startswith("artifacts/images/") for n in names))
            self.assertTrue(any(n.startswith("artifacts/manifests/") for n in names))
            self.assertTrue(any(n.startswith("artifacts/files/") for n in names))

    def test_checksums_file_matches_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "b.tar")
            payload = create_bundle(DEMO_YAML, out, pull=False)
            with tarfile.open(out) as tar:
                checks = tar.extractfile("checksums.txt").read().decode()
            for a in payload["artifacts"]:
                self.assertIn(a["sha256"], checks)


class TestInspect(unittest.TestCase):
    def test_inspect_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "b.tar")
            create_bundle(DEMO_YAML, out, pull=False)
            info = inspect_bundle(out)
            self.assertEqual(info["name"], "hello-edge")
            self.assertEqual(info["artifact_count"], 7)
            self.assertEqual(info["by_kind"]["files"], 2)
            self.assertEqual(info["by_kind"]["manifests"], 2)


class TestDeployPlan(unittest.TestCase):
    def test_plan_orders_and_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "b.tar")
            create_bundle(DEMO_YAML, out, pull=False)
            steps = plan_deploy(out, registry="reg:5000", namespace="prod")
            tools = {s["tool"] for s in steps}
            self.assertIn("docker", tools)
            self.assertIn("helm", tools)
            self.assertIn("kubectl", tools)
            # Image -> load, tag, push triplet.
            cmds = [" ".join(s["command"]) for s in steps]
            self.assertTrue(any("docker load" in c for c in cmds))
            self.assertTrue(any("docker push reg:5000/" in c for c in cmds))
            self.assertTrue(any("helm install cache" in c for c in cmds))
            self.assertTrue(any("kubectl apply -n prod" in c for c in cmds))


class TestVerifyAttestation(unittest.TestCase):
    def test_corrupt_bundle_manifest_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "b.tar")
            create_bundle(DEMO_YAML, out, pull=False)
            # Rewrite bundle.json to claim a wrong merkle root.
            corrupt = os.path.join(tmp, "c.tar")
            with tarfile.open(out) as src, tarfile.open(corrupt, "w") as dst:
                for m in src.getmembers():
                    data = src.extractfile(m).read() if m.isfile() else b""
                    if m.name == "bundle.json":
                        obj = json.loads(data.decode())
                        obj["merkle_root"] = "0" * 64
                        data = json.dumps(obj, indent=2, sort_keys=True).encode()
                        m.size = len(data)
                    dst.addfile(m, io.BytesIO(data))
            res = verify_bundle(corrupt)
            self.assertFalse(res["ok"])


class TestMcpServer(unittest.TestCase):
    def test_initialize_and_tools_list(self):
        init = mcp_server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(init["result"]["serverInfo"]["name"], "airlock")
        tl = mcp_server.handle_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in tl["result"]["tools"]}
        self.assertEqual(names, {"create", "inspect", "verify"})

    def test_tools_call_create_inspect_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "b.tar")
            r = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "create",
                           "arguments": {"manifest": DEMO_YAML, "output": out,
                                         "pull": False}}})
            self.assertFalse(r["result"]["isError"])
            r = mcp_server.handle_request({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "verify", "arguments": {"bundle": out}}})
            self.assertFalse(r["result"]["isError"])
            payload = json.loads(r["result"]["content"][0]["text"])
            self.assertTrue(payload["ok"])

    def test_unknown_method(self):
        r = mcp_server.handle_request(
            {"jsonrpc": "2.0", "id": 9, "method": "bogus"})
        self.assertIn("error", r)

    def test_notification_returns_none(self):
        r = mcp_server.handle_request(
            {"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(r)


class TestAiHook(unittest.TestCase):
    def test_draft_off_by_default(self):
        # No COGNIS_AI_* env => deterministic scaffold, never raises.
        for var in ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT"):
            os.environ.pop(var, None)
        m = draft_manifest("a web app with redis and nginx", name="demo")
        self.assertEqual(m["name"], "demo")
        for key in ("images", "charts", "manifests", "files"):
            self.assertIn(key, m)
        self.assertTrue(m["_ai"].startswith("disabled"))


if __name__ == "__main__":
    unittest.main()
