"""Command-line interface for airlock."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from airlock import TOOL_NAME, TOOL_VERSION
from airlock.core import (
    AirlockError,
    create_bundle,
    deploy_bundle,
    draft_manifest,
    inspect_bundle,
    plan_deploy,
    verify_bundle,
)


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #

def _human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.0f}{unit}" if unit == "B" else f"{f:.1f}{unit}"
        f /= 1024
    return f"{f:.1f}TB"


def _render_create(payload: dict) -> str:
    lines = []
    lines.append(f"airlock bundle created — {payload['name']} v{payload['version']}")
    lines.append("=" * 68)
    for a in payload["artifacts"]:
        flag = "OK " if a["status"] == "packed" else "REC"
        lines.append(f"[{flag}] {a['kind']:<9} {a['name']}")
        lines.append(f"        {a['sha256'][:16]}…  {_human_size(a['size'])}  ({a['note']})")
    lines.append("-" * 68)
    lines.append(f"artifacts={payload['artifact_count']}  "
                 f"merkle_root={payload['merkle_root'][:16]}…")
    return "\n".join(lines)


def _render_inspect(info: dict) -> str:
    lines = []
    lines.append(f"airlock inspect — {info['name']} v{info['version']}")
    lines.append(f"  {info.get('description') or ''}")
    lines.append("=" * 68)
    lines.append(f"format={info['format']}  built-by airlock {info['tool_version']}")
    lines.append(f"merkle_root={info['merkle_root']}")
    by = info["by_kind"]
    lines.append("by kind: " + ", ".join(f"{k}={v}" for k, v in sorted(by.items())))
    lines.append("-" * 68)
    lines.append(f"{'KIND':<10}{'STATUS':<10}{'SIZE':>9}  SHA256          NAME")
    for a in info["artifacts"]:
        lines.append(
            f"{a['kind']:<10}{a['status']:<10}{_human_size(int(a.get('size') or 0)):>9}  "
            f"{a['sha256'][:14]}  {a['name']}")
    lines.append("-" * 68)
    lines.append(f"{info['artifact_count']} artifact(s), "
                 f"{_human_size(info['total_artifact_bytes'])} total")
    return "\n".join(lines)


def _render_verify(res: dict) -> str:
    lines = []
    lines.append(f"airlock verify — {os.path.basename(res['bundle'])}")
    lines.append("=" * 68)
    lines.append(f"artifacts checked: {res['checked']}")
    if res["ok"]:
        lines.append("RESULT: PASS — every artifact hash + Merkle root match.")
    else:
        for p in res["problems"]:
            lines.append(f"  ! {p}")
        lines.append(f"RESULT: FAIL — {len(res['problems'])} integrity problem(s).")
    return "\n".join(lines)


def _render_deploy(res: dict) -> str:
    lines = []
    mode = "DRY RUN — commands only, nothing executed" if res["dry_run"] else "EXECUTED"
    lines.append(f"airlock deploy — {os.path.basename(res['bundle'])}  [{mode}]")
    lines.append("=" * 68)
    for step in res["steps"]:
        lines.append("  $ " + " ".join(_quote(c) for c in step["command"]))
    if not res["dry_run"]:
        lines.append("-" * 68)
        for e in res["executed"]:
            ok = "ok" if e.get("returncode") == 0 else f"rc={e.get('returncode')}"
            lines.append(f"  [{ok}] {e['tool']} {e['kind']} {e['name']}")
        for s in res["skipped"]:
            lines.append(f"  [skip] {s['name']} — {s['reason']}")
    return "\n".join(lines)


def _quote(s: str) -> str:
    return f'"{s}"' if (" " in s or not s) else s


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


# --------------------------------------------------------------------------- #
# Argument parser
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Declarative air-gapped software delivery — bundle OCI "
                    "images, Helm charts, and manifests into one verifiable "
                    "archive for disconnected clusters.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    c = sub.add_parser("create", help="Resolve a manifest into a portable bundle.tar")
    c.add_argument("manifest", help="Path to airlock.yaml / airlock.json")
    c.add_argument("-o", "--output", default="bundle.tar",
                   help="Output archive path (default: bundle.tar)")
    c.add_argument("--no-pull", action="store_true",
                   help="Do not shell out to docker/helm; record intent only.")
    c.add_argument("--format", choices=("table", "json"), default="table")
    c.add_argument("--out", help="Write report to this file instead of stdout.")

    i = sub.add_parser("inspect", help="List a bundle's contents, sizes, and hashes.")
    i.add_argument("bundle", help="Path to a bundle.tar")
    i.add_argument("--format", choices=("table", "json"), default="table")
    i.add_argument("--out", help="Write report to this file instead of stdout.")

    v = sub.add_parser("verify", help="Recompute and check every artifact's sha256.")
    v.add_argument("bundle", help="Path to a bundle.tar")
    v.add_argument("--format", choices=("table", "json"), default="table")
    v.add_argument("--out", help="Write report to this file instead of stdout.")

    d = sub.add_parser("deploy", help="Plan/seed a disconnected cluster from a bundle.")
    d.add_argument("bundle", help="Path to a bundle.tar")
    d.add_argument("--dry-run", action="store_true",
                   help="Print the docker/helm/kubectl commands without running.")
    d.add_argument("--registry", default="localhost:5000",
                   help="Target in-cluster registry (default: localhost:5000)")
    d.add_argument("--namespace", default="default",
                   help="Target namespace for charts/manifests (default: default)")
    d.add_argument("--format", choices=("table", "json"), default="table")
    d.add_argument("--out", help="Write report to this file instead of stdout.")

    a = sub.add_parser("draft", help="Draft an airlock manifest from plain English (--ai).")
    a.add_argument("description", help="Plain-English app description.")
    a.add_argument("--name", default="drafted-app", help="Bundle name.")
    a.add_argument("--ai", action="store_true",
                   help="Enable the local-fleet LLM hook (default OFF: scaffold only).")
    a.add_argument("--out", help="Write the drafted manifest to this file.")

    sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    return p


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #

def _run_create(args) -> int:
    try:
        payload = create_bundle(args.manifest, args.output, pull=not args.no_pull)
    except (OSError, AirlockError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        _emit(json.dumps(payload, indent=2), args.out)
    else:
        _emit(_render_create(payload), args.out)
        print(f"wrote {args.output}", file=sys.stderr)
    return 0


def _run_inspect(args) -> int:
    try:
        info = inspect_bundle(args.bundle)
    except (OSError, AirlockError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        _emit(json.dumps(info, indent=2), args.out)
    else:
        _emit(_render_inspect(info), args.out)
    return 0


def _run_verify(args) -> int:
    try:
        res = verify_bundle(args.bundle)
    except (OSError, AirlockError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        _emit(json.dumps(res, indent=2), args.out)
    else:
        _emit(_render_verify(res), args.out)
    return 0 if res["ok"] else 1


def _run_deploy(args) -> int:
    try:
        if args.dry_run:
            steps = plan_deploy(args.bundle, registry=args.registry,
                                namespace=args.namespace)
            res = {"bundle": args.bundle, "dry_run": True, "steps": steps,
                   "executed": [], "skipped": []}
        else:
            res = deploy_bundle(args.bundle, registry=args.registry,
                                namespace=args.namespace, dry_run=False)
    except (OSError, AirlockError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        _emit(json.dumps(res, indent=2), args.out)
    else:
        _emit(_render_deploy(res), args.out)
    if not res["dry_run"]:
        for e in res.get("executed", []):
            if e.get("returncode") not in (0, None):
                return 1
    return 0


def _run_draft(args) -> int:
    if args.ai and not os.environ.get("COGNIS_AI_BACKEND") \
            and not os.environ.get("COGNIS_AI_ENDPOINT"):
        print("note: --ai given but no COGNIS_AI_BACKEND/ENDPOINT configured; "
              "emitting deterministic scaffold.", file=sys.stderr)
    manifest = draft_manifest(args.description, name=args.name)
    text = json.dumps(manifest, indent=2)
    _emit(text, args.out)
    return 0


def _run_mcp() -> int:
    from airlock.mcp_server import run_mcp_server
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "create":
        return _run_create(args)
    if args.command == "inspect":
        return _run_inspect(args)
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "deploy":
        return _run_deploy(args)
    if args.command == "draft":
        return _run_draft(args)
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
