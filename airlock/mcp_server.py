"""airlock MCP server.

Exposes the air-gap bundler over stdio using newline-delimited JSON-RPC 2.0.
Standard library only — no SDK required — so it runs anywhere Python does and
can be wired into Cognis.Studio, Claude Desktop, or Cursor as a local MCP
server:

    {"command": "python", "args": ["-m", "airlock", "mcp"]}

Implemented methods:
  * initialize  — handshake, advertises the tools capability
  * tools/list  — describes create / inspect / verify
  * tools/call  — runs a tool and returns its result as JSON text

Each line on stdin is one JSON-RPC request; each response is one JSON line on
stdout.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from airlock import TOOL_NAME, TOOL_VERSION
from airlock.core import (
    AirlockError,
    create_bundle,
    inspect_bundle,
    verify_bundle,
)

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "create",
        "description": "Resolve a declarative airlock manifest (yaml/json) into "
                       "one portable, integrity-verified tar bundle of OCI "
                       "images, Helm charts, k8s manifests, and files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {"type": "string",
                             "description": "Path to airlock.yaml / airlock.json."},
                "output": {"type": "string",
                           "description": "Output bundle.tar path."},
                "pull": {"type": "boolean",
                         "description": "Shell out to docker/helm to pull real "
                                        "artifacts (default true)."},
            },
            "required": ["manifest"],
            "additionalProperties": False,
        },
    },
    {
        "name": "inspect",
        "description": "List a bundle's contents, sizes, sha256 hashes, and "
                       "its bundle manifest.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle": {"type": "string", "description": "Path to bundle.tar."},
            },
            "required": ["bundle"],
            "additionalProperties": False,
        },
    },
    {
        "name": "verify",
        "description": "Recompute every artifact's sha256 and the Merkle root "
                       "against the bundle manifest; reports tamper/integrity "
                       "problems.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle": {"type": "string", "description": "Path to bundle.tar."},
            },
            "required": ["bundle"],
            "additionalProperties": False,
        },
    },
]


def _result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "create":
        manifest = arguments.get("manifest")
        if not isinstance(manifest, str) or not manifest:
            raise ValueError("`manifest` (string path) is required")
        output = arguments.get("output") or "bundle.tar"
        pull = arguments.get("pull", True)
        payload = create_bundle(manifest, output, pull=bool(pull))
        is_error = False
    elif name == "inspect":
        bundle = arguments.get("bundle")
        if not isinstance(bundle, str) or not bundle:
            raise ValueError("`bundle` (string path) is required")
        payload = inspect_bundle(bundle)
        is_error = False
    elif name == "verify":
        bundle = arguments.get("bundle")
        if not isinstance(bundle, str) or not bundle:
            raise ValueError("`bundle` (string path) is required")
        payload = verify_bundle(bundle)
        is_error = not payload.get("ok", False)
    else:
        raise ValueError(f"unknown tool: {name}")

    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "isError": is_error,
    }


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch a single JSON-RPC request. Returns None for notifications."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}
    is_notification = "id" not in req

    if method == "initialize":
        res = _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
        return None if is_notification else res

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, arguments))
        except (ValueError, OSError, AirlockError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            return _error(req_id, -32603, f"internal error: {exc}")

    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
