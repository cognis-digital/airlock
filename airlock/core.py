"""Core engine for airlock — declarative air-gapped software delivery.

airlock turns a single declarative manifest (``airlock.yaml`` / ``airlock.json``)
into ONE portable, integrity-verified archive that can be carried across an
air-gap and replayed into a disconnected Kubernetes cluster.

The manifest declares four kinds of artifact:

  * ``images``    — OCI/container images to pull and ship
  * ``charts``    — Helm charts (name + repo + version) to fetch and ship
  * ``manifests`` — raw Kubernetes YAML/JSON files to ship and ``kubectl apply``
  * ``files``     — arbitrary files/blobs to carry along

``create`` gathers everything into a tar archive with a deterministic internal
layout, computing a SHA-256 for every artifact. The bundle carries its own
``bundle.json`` (the resolved manifest + artifact index) and ``checksums.txt``.
A detached ``attestation.json`` records a Merkle-style root over the artifact
hashes so tampering anywhere in the tree is detectable.

Where airlock must fetch *real* images/charts it shells out to ``docker``/``oras``
/``helm`` when present; when those tools are absent (the common offline-demo
case) it records the declared intent and still produces a structurally valid,
verifiable bundle from any local files the manifest references. Nothing here
requires network access for the demo path, and the module is standard-library
only.

This is original Cognis Digital work. It is conceptually a declarative
air-gap packager but shares no code, naming, or branding with any other tool.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Tool identity (re-exported from the package __init__).
TOOL_NAME = "airlock"
TOOL_VERSION = "0.1.0"

# Internal archive layout. Everything an airlock bundle ships lives under one of
# these prefixes; the two control files sit at the archive root.
LAYOUT = {
    "images": "artifacts/images",
    "charts": "artifacts/charts",
    "manifests": "artifacts/manifests",
    "files": "artifacts/files",
}
BUNDLE_MANIFEST = "bundle.json"
CHECKSUMS_FILE = "checksums.txt"
ATTESTATION_FILE = "attestation.json"

BUNDLE_FORMAT = "cognis.airlock.bundle/v1"


class AirlockError(Exception):
    """Raised for any manifest / bundle problem surfaced to the user."""


# --------------------------------------------------------------------------- #
# Tiny stdlib YAML-subset parser
# --------------------------------------------------------------------------- #
# airlock manifests use a small, well-defined YAML subset (mappings, lists,
# scalars, two-space indentation, ``#`` comments). This avoids a PyYAML
# dependency while still letting users write natural YAML. JSON manifests are
# also accepted directly.

def _coerce_scalar(text: str) -> Any:
    s = text.strip()
    if s == "" or s in ("~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if (len(s) >= 2) and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment that is not inside quotes."""
    in_single = in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            # Only treat as a comment if preceded by start-of-line or space.
            if i == 0 or line[i - 1] in " \t":
                return line[:i]
    return line


def parse_yaml_subset(text: str) -> Any:
    """Parse the supported YAML subset into Python data structures.

    Supports: nested mappings, block lists (``- item``), inline ``key: value``
    list items, scalars (str/int/float/bool/null), quoted strings, comments,
    and blank lines. Indentation is significant and must be consistent. This is
    deliberately small; anything fancier should be expressed as JSON.
    """
    # Normalize and pre-tokenize lines into (indent, content) keeping order.
    raw_lines = text.replace("\t", "  ").splitlines()
    tokens: List[Tuple[int, str]] = []
    for raw in raw_lines:
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        if stripped.strip() == "---":
            continue  # single-document only; ignore document markers
        indent = len(stripped) - len(stripped.lstrip(" "))
        tokens.append((indent, stripped.strip()))

    if not tokens:
        return {}

    pos = 0

    def parse_block(min_indent: int) -> Any:
        nonlocal pos
        if pos >= len(tokens):
            return None
        indent, content = tokens[pos]
        if content.startswith("- "):
            return parse_list(indent)
        return parse_map(indent)

    def parse_list(indent: int) -> List[Any]:
        nonlocal pos
        items: List[Any] = []
        while pos < len(tokens):
            cur_indent, content = tokens[pos]
            if cur_indent != indent or not content.startswith("- "):
                if cur_indent < indent:
                    break
                if not content.startswith("- ") and cur_indent <= indent:
                    break
            inner = content[2:].strip()
            pos += 1
            if ":" in inner and not _looks_like_plain_scalar(inner):
                # Inline mapping start on the dash line, e.g. "- name: x".
                # Re-inject this as the first key of a map at indent+2.
                key, val = _split_kv(inner)
                obj: Dict[str, Any] = {}
                if val == "":
                    child = _maybe_parse_child(indent + 2)
                    obj[key] = child
                else:
                    obj[key] = _coerce_scalar(val)
                # Consume sibling keys belonging to this list item.
                obj.update(_consume_map_continuation(indent + 2))
                items.append(obj)
            elif inner == "":
                items.append(_maybe_parse_child(indent + 2))
            else:
                items.append(_coerce_scalar(inner))
        return items

    def parse_map(indent: int) -> Dict[str, Any]:
        nonlocal pos
        obj: Dict[str, Any] = {}
        while pos < len(tokens):
            cur_indent, content = tokens[pos]
            if cur_indent != indent:
                break
            if content.startswith("- "):
                break
            key, val = _split_kv(content)
            pos += 1
            if val == "":
                child = _maybe_parse_child(indent + 1)
                obj[key] = child
            else:
                obj[key] = _coerce_scalar(val)
        return obj

    def _consume_map_continuation(indent: int) -> Dict[str, Any]:
        nonlocal pos
        obj: Dict[str, Any] = {}
        while pos < len(tokens):
            cur_indent, content = tokens[pos]
            if cur_indent < indent or content.startswith("- "):
                break
            if cur_indent != indent:
                break
            key, val = _split_kv(content)
            pos += 1
            if val == "":
                obj[key] = _maybe_parse_child(indent + 2)
            else:
                obj[key] = _coerce_scalar(val)
        return obj

    def _maybe_parse_child(child_min_indent: int) -> Any:
        nonlocal pos
        if pos >= len(tokens):
            return None
        cur_indent, content = tokens[pos]
        if cur_indent < child_min_indent:
            return None
        if content.startswith("- "):
            return parse_list(cur_indent)
        return parse_map(cur_indent)

    result = parse_block(0)
    return result if result is not None else {}


def _split_kv(content: str) -> Tuple[str, str]:
    idx = content.find(":")
    if idx == -1:
        return content.strip(), ""
    key = content[:idx].strip()
    val = content[idx + 1:].strip()
    if (len(key) >= 2) and ((key[0] == key[-1] == '"') or (key[0] == key[-1] == "'")):
        key = key[1:-1]
    return key, val


def _looks_like_plain_scalar(text: str) -> bool:
    # A list item like "- http://x:y" has a colon but is a plain scalar, not a
    # mapping. Treat as scalar when the part before ':' contains a space or the
    # colon is glued (no following space) — i.e. it is a URL/host:port.
    idx = text.find(":")
    if idx == -1:
        return True
    after = text[idx + 1:]
    if after and not after.startswith(" "):
        return True
    return False


# --------------------------------------------------------------------------- #
# Manifest loading + normalization
# --------------------------------------------------------------------------- #

@dataclass
class Artifact:
    """One resolved artifact slated for the bundle."""
    kind: str                       # images|charts|manifests|files
    name: str                       # logical identifier (image ref, chart name…)
    arcname: str = ""               # path inside the archive (set at pack time)
    source: Optional[str] = None    # local file path that backs this artifact
    spec: Dict[str, Any] = field(default_factory=dict)  # declared fields
    sha256: str = ""
    size: int = 0
    status: str = "declared"        # declared|packed|recorded(intent-only)
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "arcname": self.arcname,
            "sha256": self.sha256,
            "size": self.size,
            "status": self.status,
            "note": self.note,
            "spec": self.spec,
        }


def load_manifest(path: str) -> Dict[str, Any]:
    """Load an airlock manifest from a ``.json``/``.yaml``/``.yml`` file."""
    if not os.path.isfile(path):
        raise AirlockError(f"manifest not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".json":
            data = json.loads(text)
        elif ext in (".yaml", ".yml"):
            data = parse_yaml_subset(text)
        else:
            # Sniff: JSON if it starts with { or [.
            t = text.lstrip()
            data = json.loads(text) if t[:1] in "{[" else parse_yaml_subset(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise AirlockError(f"could not parse manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AirlockError("manifest root must be a mapping/object")
    return data


def resolve_artifacts(manifest: Dict[str, Any], base_dir: str) -> List[Artifact]:
    """Translate a manifest into a flat, ordered list of Artifacts.

    ``base_dir`` is the directory the manifest lives in; relative file paths in
    the manifest are resolved against it.
    """
    arts: List[Artifact] = []

    def _resolve_path(p: str) -> Optional[str]:
        if not p:
            return None
        cand = p if os.path.isabs(p) else os.path.join(base_dir, p)
        return cand if os.path.exists(cand) else None

    # images: list of strings or {ref, ...}
    for entry in manifest.get("images") or []:
        if isinstance(entry, str):
            ref, spec, src = entry, {"ref": entry}, None
        elif isinstance(entry, dict):
            ref = entry.get("ref") or entry.get("image") or entry.get("name") or ""
            spec = dict(entry)
            src = _resolve_path(entry.get("path") or entry.get("file") or "")
        else:
            continue
        if not ref:
            raise AirlockError("image entry missing a 'ref'")
        arts.append(Artifact(kind="images", name=ref, source=src, spec=spec))

    # charts: {name, repo, version, [path]}
    for entry in manifest.get("charts") or []:
        if not isinstance(entry, dict):
            raise AirlockError("chart entries must be mappings (name/repo/version)")
        name = entry.get("name") or ""
        if not name:
            raise AirlockError("chart entry missing 'name'")
        src = _resolve_path(entry.get("path") or entry.get("file") or "")
        arts.append(Artifact(kind="charts", name=name, source=src, spec=dict(entry)))

    # manifests: list of file paths (or {path,...})
    for entry in manifest.get("manifests") or []:
        if isinstance(entry, str):
            path, spec = entry, {"path": entry}
        elif isinstance(entry, dict):
            path, spec = (entry.get("path") or entry.get("file") or ""), dict(entry)
        else:
            continue
        if not path:
            raise AirlockError("manifest entry missing 'path'")
        src = _resolve_path(path)
        if src is None:
            raise AirlockError(f"k8s manifest file not found: {path}")
        arts.append(Artifact(kind="manifests", name=os.path.basename(path),
                             source=src, spec=spec))

    # files: list of file paths (or {path, [dest]})
    for entry in manifest.get("files") or []:
        if isinstance(entry, str):
            path, spec = entry, {"path": entry}
        elif isinstance(entry, dict):
            path, spec = (entry.get("path") or entry.get("file") or ""), dict(entry)
        else:
            continue
        if not path:
            raise AirlockError("file entry missing 'path'")
        src = _resolve_path(path)
        if src is None:
            raise AirlockError(f"file not found: {path}")
        arts.append(Artifact(kind="files", name=os.path.basename(path),
                            source=src, spec=spec))

    return arts


# --------------------------------------------------------------------------- #
# Hashing helpers
# --------------------------------------------------------------------------- #

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def merkle_root(leaf_hashes: List[str]) -> str:
    """Compute a simple binary Merkle root over hex leaf hashes.

    Empty -> sha256 of empty string. Odd levels duplicate the last node. This
    gives a single root that changes if ANY artifact hash changes.
    """
    if not leaf_hashes:
        return sha256_bytes(b"")
    level = [bytes.fromhex(h) for h in sorted(leaf_hashes)]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = nxt
    return level[0].hex()


# --------------------------------------------------------------------------- #
# External tool detection (graceful / offline-friendly)
# --------------------------------------------------------------------------- #

def _which(tool: str) -> Optional[str]:
    return shutil.which(tool)


def _try_export_image(ref: str, dest_tar: str) -> Tuple[bool, str]:
    """Attempt to materialize an OCI image to ``dest_tar`` via docker/oras.

    Returns (ok, note). Never raises; on any failure returns (False, reason) so
    create() can fall back to recording the intent. Pulls then saves.
    """
    docker = _which("docker")
    if docker:
        try:
            subprocess.run([docker, "pull", ref], check=True,
                           capture_output=True, timeout=600)
            subprocess.run([docker, "save", "-o", dest_tar, ref], check=True,
                           capture_output=True, timeout=600)
            if os.path.isfile(dest_tar) and os.path.getsize(dest_tar) > 0:
                return True, "exported via docker save"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                OSError) as exc:
            return False, f"docker export failed: {exc}"
    oras = _which("oras")
    if oras:
        try:
            subprocess.run([oras, "pull", ref, "-o", os.path.dirname(dest_tar)],
                           check=True, capture_output=True, timeout=600)
            return True, "pulled via oras"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                OSError) as exc:
            return False, f"oras pull failed: {exc}"
    return False, "no docker/oras on PATH — recorded image intent only"


def _try_export_chart(spec: Dict[str, Any], dest_dir: str) -> Tuple[bool, str, Optional[str]]:
    """Attempt to fetch a Helm chart tgz via ``helm pull``.

    Returns (ok, note, packed_path). Never raises.
    """
    helm = _which("helm")
    name = spec.get("name") or ""
    repo = spec.get("repo") or ""
    version = spec.get("version") or ""
    if not helm or not repo:
        return False, "no helm/repo — recorded chart intent only", None
    try:
        cmd = [helm, "pull", name, "--repo", repo, "--destination", dest_dir]
        if version:
            cmd += ["--version", str(version)]
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)
        # Find the produced .tgz.
        for fn in os.listdir(dest_dir):
            if fn.endswith(".tgz") and name in fn:
                return True, "pulled via helm", os.path.join(dest_dir, fn)
        return False, "helm pull produced no tgz", None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        return False, f"helm pull failed: {exc}", None


# --------------------------------------------------------------------------- #
# create
# --------------------------------------------------------------------------- #

def create_bundle(manifest_path: str, output: str,
                  pull: bool = True) -> Dict[str, Any]:
    """Gather declared artifacts into one portable, verifiable tar bundle.

    Returns the bundle.json payload that was written into the archive.
    """
    manifest = load_manifest(manifest_path)
    base_dir = os.path.dirname(os.path.abspath(manifest_path))
    arts = resolve_artifacts(manifest, base_dir)

    meta = {
        "format": BUNDLE_FORMAT,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "name": manifest.get("name") or "unnamed",
        "version": str(manifest.get("version") or "0.0.0"),
        "description": manifest.get("description") or "",
        "created_utc": int(time.time()),
    }

    # Stage artifacts into a temp working dir mirroring the archive layout, then
    # write everything in a single deterministic tar pass.
    work = output + ".work"
    if os.path.isdir(work):
        shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work, exist_ok=True)

    index: List[Dict[str, Any]] = []
    try:
        for i, art in enumerate(arts):
            staged = _stage_artifact(art, work, pull=pull, ordinal=i)
            index.append(staged)

        leaf_hashes = [a["sha256"] for a in index if a["sha256"]]
        bundle_payload = {
            **meta,
            "artifact_count": len(index),
            "artifacts": index,
            "merkle_root": merkle_root(leaf_hashes),
        }

        # checksums.txt — "<sha256>  <arcname>" lines, sorted for determinism.
        checksum_lines = sorted(
            f"{a['sha256']}  {a['arcname']}" for a in index if a["arcname"]
        )
        checksums_text = "\n".join(checksum_lines) + ("\n" if checksum_lines else "")

        # attestation.json — detached integrity statement over the bundle.
        bundle_json_bytes = json.dumps(bundle_payload, indent=2,
                                       sort_keys=True).encode("utf-8")
        attestation = {
            "format": "cognis.airlock.attestation/v1",
            "subject": meta["name"],
            "subject_version": meta["version"],
            "merkle_root": bundle_payload["merkle_root"],
            "bundle_manifest_sha256": sha256_bytes(bundle_json_bytes),
            "checksums_sha256": sha256_bytes(checksums_text.encode("utf-8")),
            "artifact_count": len(index),
            "created_utc": meta["created_utc"],
            "issuer": "cognis-digital/airlock",
        }
        attestation_bytes = json.dumps(attestation, indent=2,
                                       sort_keys=True).encode("utf-8")

        # Write the tar.
        _write_tar(output, work, index, bundle_json_bytes,
                   checksums_text.encode("utf-8"), attestation_bytes)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    return bundle_payload


def _stage_artifact(art: Artifact, work: str, pull: bool,
                    ordinal: int) -> Dict[str, Any]:
    """Materialize one artifact into the work tree; return its index entry."""
    subdir = LAYOUT[art.kind]
    dest_root = os.path.join(work, *subdir.split("/"))
    os.makedirs(dest_root, exist_ok=True)

    if art.kind == "images":
        safe = _safe_name(art.name) + ".tar"
        dest = os.path.join(dest_root, safe)
        ok = False
        note = ""
        if pull and art.source is None:
            ok, note = _try_export_image(art.name, dest)
        if not ok and art.source and os.path.isfile(art.source):
            shutil.copyfile(art.source, dest)
            ok, note = True, "packed from local image tar"
        if not ok:
            # Intent-only: write a small descriptor so the bundle still records
            # what must be loaded on the far side.
            descriptor = json.dumps(
                {"image": art.name, "spec": art.spec, "status": "intent"},
                indent=2).encode("utf-8")
            dest = os.path.join(dest_root, _safe_name(art.name) + ".intent.json")
            with open(dest, "wb") as fh:
                fh.write(descriptor)
            status = "recorded"
            note = note or "recorded image intent only"
        else:
            status = "packed"
        arcname = f"{subdir}/{os.path.basename(dest)}"
        return _index_entry(art, dest, arcname, status, note)

    if art.kind == "charts":
        chart_dir = os.path.join(dest_root, _safe_name(art.name))
        os.makedirs(chart_dir, exist_ok=True)
        packed_path = None
        note = ""
        if art.source and os.path.isfile(art.source):
            dest = os.path.join(chart_dir, os.path.basename(art.source))
            shutil.copyfile(art.source, dest)
            packed_path, note, status = dest, "packed from local chart file", "packed"
        elif pull:
            ok, note, pp = _try_export_chart(art.spec, chart_dir)
            if ok and pp:
                packed_path, status = pp, "packed"
            else:
                packed_path, status = None, "recorded"
        else:
            status = "recorded"
        if packed_path is None:
            descriptor = json.dumps(
                {"chart": art.name, "spec": art.spec, "status": "intent"},
                indent=2).encode("utf-8")
            packed_path = os.path.join(chart_dir, "chart.intent.json")
            with open(packed_path, "wb") as fh:
                fh.write(descriptor)
            note = note or "recorded chart intent only"
            status = "recorded"
        rel = os.path.relpath(packed_path, work).replace(os.sep, "/")
        return _index_entry(art, packed_path, rel, status, note)

    # manifests / files — straight copy of a verified-present local file.
    safe = _safe_name(art.name)
    dest = os.path.join(dest_root, safe)
    # Avoid collisions across identically named files.
    if os.path.exists(dest):
        dest = os.path.join(dest_root, f"{ordinal:03d}-{safe}")
    shutil.copyfile(art.source, dest)
    arcname = f"{subdir}/{os.path.basename(dest)}"
    return _index_entry(art, dest, arcname, "packed", "packed local file")


def _index_entry(art: Artifact, real_path: str, arcname: str,
                 status: str, note: str) -> Dict[str, Any]:
    art.sha256 = sha256_file(real_path)
    art.size = os.path.getsize(real_path)
    art.arcname = arcname
    art.status = status
    art.note = note
    return art.to_dict()


def _safe_name(name: str) -> str:
    out = []
    for ch in name:
        out.append(ch if (ch.isalnum() or ch in "._-") else "_")
    return "".join(out) or "artifact"


def _write_tar(output: str, work: str, index: List[Dict[str, Any]],
               bundle_json: bytes, checksums: bytes, attestation: bytes) -> None:
    with tarfile.open(output, "w") as tar:
        # Control files first.
        _add_bytes(tar, BUNDLE_MANIFEST, bundle_json)
        _add_bytes(tar, CHECKSUMS_FILE, checksums)
        _add_bytes(tar, ATTESTATION_FILE, attestation)
        # Artifacts, in index order.
        for entry in index:
            arc = entry["arcname"]
            real = os.path.join(work, *arc.split("/"))
            if os.path.isfile(real):
                tar.add(real, arcname=arc)


def _add_bytes(tar: tarfile.TarFile, arcname: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=arcname)
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    tar.addfile(info, io.BytesIO(data))


# --------------------------------------------------------------------------- #
# inspect / verify
# --------------------------------------------------------------------------- #

def _read_bundle_meta(bundle_path: str) -> Dict[str, Any]:
    if not os.path.isfile(bundle_path):
        raise AirlockError(f"bundle not found: {bundle_path}")
    try:
        with tarfile.open(bundle_path, "r") as tar:
            member = tar.extractfile(BUNDLE_MANIFEST)
            if member is None:
                raise AirlockError("bundle has no bundle.json (not an airlock bundle)")
            return json.loads(member.read().decode("utf-8"))
    except tarfile.TarError as exc:
        raise AirlockError(f"could not read bundle {bundle_path}: {exc}") from exc


def inspect_bundle(bundle_path: str) -> Dict[str, Any]:
    """Return the bundle manifest plus a per-artifact size/hash summary."""
    meta = _read_bundle_meta(bundle_path)
    arts = meta.get("artifacts", [])
    by_kind: Dict[str, int] = {}
    total = 0
    for a in arts:
        by_kind[a["kind"]] = by_kind.get(a["kind"], 0) + 1
        total += int(a.get("size") or 0)
    return {
        "bundle": bundle_path,
        "name": meta.get("name"),
        "version": meta.get("version"),
        "description": meta.get("description"),
        "format": meta.get("format"),
        "tool_version": meta.get("tool_version"),
        "created_utc": meta.get("created_utc"),
        "merkle_root": meta.get("merkle_root"),
        "artifact_count": meta.get("artifact_count", len(arts)),
        "total_artifact_bytes": total,
        "by_kind": by_kind,
        "artifacts": arts,
    }


def verify_bundle(bundle_path: str) -> Dict[str, Any]:
    """Recompute every artifact's sha256 from the archive and compare.

    Also recomputes the Merkle root and cross-checks the detached attestation
    when present. Returns a result dict; ``ok`` is False on any mismatch.
    """
    if not os.path.isfile(bundle_path):
        raise AirlockError(f"bundle not found: {bundle_path}")

    problems: List[str] = []
    checked = 0
    recomputed_hashes: List[str] = []

    try:
        with tarfile.open(bundle_path, "r") as tar:
            names = set(tar.getnames())
            meta_member = tar.extractfile(BUNDLE_MANIFEST)
            if meta_member is None:
                raise AirlockError("bundle has no bundle.json")
            meta_raw = meta_member.read()
            meta = json.loads(meta_raw.decode("utf-8"))

            for a in meta.get("artifacts", []):
                arc = a.get("arcname")
                declared = a.get("sha256")
                if not arc:
                    continue
                if arc not in names:
                    problems.append(f"missing artifact in archive: {arc}")
                    continue
                member = tar.extractfile(arc)
                if member is None:
                    problems.append(f"unreadable artifact: {arc}")
                    continue
                actual = sha256_bytes(member.read())
                recomputed_hashes.append(actual)
                checked += 1
                if declared and actual != declared:
                    problems.append(
                        f"sha256 mismatch for {arc}: "
                        f"declared {declared[:12]}… actual {actual[:12]}…")

            # Merkle root recomputation.
            declared_root = meta.get("merkle_root")
            actual_root = merkle_root(recomputed_hashes)
            if declared_root and declared_root != actual_root:
                problems.append(
                    f"merkle root mismatch: declared {declared_root[:12]}… "
                    f"recomputed {actual_root[:12]}…")

            # Attestation cross-check (if present).
            if ATTESTATION_FILE in names:
                att_member = tar.extractfile(ATTESTATION_FILE)
                if att_member is not None:
                    att = json.loads(att_member.read().decode("utf-8"))
                    # bundle.json was serialized sort_keys=True at create time.
                    canon = json.dumps(meta, indent=2, sort_keys=True).encode("utf-8")
                    if att.get("bundle_manifest_sha256") and \
                       att["bundle_manifest_sha256"] != sha256_bytes(canon):
                        problems.append("attestation: bundle.json hash mismatch")
                    if att.get("merkle_root") and att["merkle_root"] != actual_root:
                        problems.append("attestation: merkle root mismatch")
    except tarfile.TarError as exc:
        raise AirlockError(f"could not read bundle {bundle_path}: {exc}") from exc

    return {
        "bundle": bundle_path,
        "ok": not problems,
        "checked": checked,
        "problems": problems,
    }


# --------------------------------------------------------------------------- #
# deploy (dry-run by default)
# --------------------------------------------------------------------------- #

def plan_deploy(bundle_path: str, registry: str = "localhost:5000",
                namespace: str = "default") -> List[Dict[str, Any]]:
    """Compute the ordered command plan to seed a disconnected cluster.

    Returns a list of step dicts: {kind, name, command (list[str]), tool}.
    No commands are executed here — this is what ``deploy --dry-run`` prints.
    """
    meta = _read_bundle_meta(bundle_path)
    steps: List[Dict[str, Any]] = []
    for a in meta.get("artifacts", []):
        kind, name, arc = a["kind"], a["name"], a.get("arcname", "")
        if kind == "images":
            target = f"{registry}/{_repo_tail(name)}"
            steps.append({
                "kind": "image", "name": name, "tool": "docker",
                "command": ["docker", "load", "-i", arc],
            })
            steps.append({
                "kind": "image", "name": name, "tool": "docker",
                "command": ["docker", "tag", name, target],
            })
            steps.append({
                "kind": "image", "name": name, "tool": "docker",
                "command": ["docker", "push", target],
            })
        elif kind == "charts":
            spec = a.get("spec", {})
            release = spec.get("release") or _safe_name(name)
            steps.append({
                "kind": "chart", "name": name, "tool": "helm",
                "command": ["helm", "install", release, arc,
                            "--namespace", namespace, "--create-namespace"],
            })
        elif kind == "manifests":
            steps.append({
                "kind": "manifest", "name": name, "tool": "kubectl",
                "command": ["kubectl", "apply", "-n", namespace, "-f", arc],
            })
        # files are carried but not auto-applied.
    return steps


def _repo_tail(ref: str) -> str:
    # Strip a registry host prefix from an image ref for re-tagging.
    body = ref.split("@", 1)[0]
    parts = body.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0]):
        return "/".join(parts[1:])
    return body


def deploy_bundle(bundle_path: str, registry: str = "localhost:5000",
                  namespace: str = "default", dry_run: bool = True) -> Dict[str, Any]:
    """Execute (or with dry_run, just plan) the deploy steps.

    When not dry-run, extracts the archive to a temp dir and runs each step's
    command — but only for steps whose CLI tool is present on PATH; missing
    tools yield skipped steps rather than failures.
    """
    steps = plan_deploy(bundle_path, registry=registry, namespace=namespace)
    if dry_run:
        return {"bundle": bundle_path, "dry_run": True, "steps": steps,
                "executed": [], "skipped": []}

    extract_dir = bundle_path + ".deploy"
    os.makedirs(extract_dir, exist_ok=True)
    executed: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    try:
        with tarfile.open(bundle_path, "r") as tar:
            _safe_extract(tar, extract_dir)
        for step in steps:
            tool = step["tool"]
            if _which(tool) is None:
                skipped.append({**step, "reason": f"{tool} not on PATH"})
                continue
            cmd = list(step["command"])
            # Rewrite archive-relative artifact paths to the extracted location.
            cmd = [os.path.join(extract_dir, *p.split("/"))
                   if (p.startswith("artifacts/")) else p for p in cmd]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=600)
                executed.append({**step, "returncode": proc.returncode,
                                 "stderr": proc.stderr[-2000:]})
            except (subprocess.TimeoutExpired, OSError) as exc:
                executed.append({**step, "returncode": 1, "stderr": str(exc)})
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
    return {"bundle": bundle_path, "dry_run": False, "steps": steps,
            "executed": executed, "skipped": skipped}


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    dest_abs = os.path.abspath(dest)
    for member in tar.getmembers():
        target = os.path.abspath(os.path.join(dest, member.name))
        if not target.startswith(dest_abs + os.sep) and target != dest_abs:
            raise AirlockError(f"unsafe path in bundle: {member.name}")
    tar.extractall(dest)


# --------------------------------------------------------------------------- #
# extract / diff
# --------------------------------------------------------------------------- #

def extract_bundle(bundle_path: str, dest: str,
                   verify: bool = True) -> Dict[str, Any]:
    """Unpack a bundle to ``dest`` (path-traversal-safe). Optionally verify first.

    Returns {dest, extracted, verified}. Raises on a failed verification.
    """
    if not os.path.isfile(bundle_path):
        raise AirlockError(f"bundle not found: {bundle_path}")
    if verify:
        res = verify_bundle(bundle_path)
        if not res["ok"]:
            raise AirlockError(
                f"refusing to extract: integrity check failed "
                f"({len(res['problems'])} problem(s))")
    os.makedirs(dest, exist_ok=True)
    count = 0
    with tarfile.open(bundle_path, "r") as tar:
        _safe_extract(tar, dest)
        count = len([m for m in tar.getmembers() if m.isfile()])
    return {"dest": dest, "extracted": count, "verified": verify}


def diff_bundles(bundle_a: str, bundle_b: str) -> Dict[str, Any]:
    """Diff two bundles by their artifact index (added / removed / changed).

    Compares the artifact name -> sha256 maps from each bundle's manifest.
    """
    ma = _read_bundle_meta(bundle_a)
    mb = _read_bundle_meta(bundle_b)
    amap = {a["name"]: a.get("sha256", "") for a in ma.get("artifacts", [])}
    bmap = {a["name"]: a.get("sha256", "") for a in mb.get("artifacts", [])}
    added = sorted(set(bmap) - set(amap))
    removed = sorted(set(amap) - set(bmap))
    changed = sorted(n for n in (set(amap) & set(bmap)) if amap[n] != bmap[n])
    return {
        "a": {"name": ma.get("name"), "version": ma.get("version"),
              "merkle_root": ma.get("merkle_root")},
        "b": {"name": mb.get("name"), "version": mb.get("version"),
              "merkle_root": mb.get("merkle_root")},
        "added": added, "removed": removed, "changed": changed,
        "identical": not (added or removed or changed),
    }


# --------------------------------------------------------------------------- #
# AI draft hook (opt-in, default OFF)
# --------------------------------------------------------------------------- #

def draft_manifest(description: str, name: str = "drafted-app") -> Dict[str, Any]:
    """Draft an airlock manifest from a plain-English app description.

    Uses the Cognis shared AI backend (local fleet, OpenAI-compatible). This is
    OFF by default: with no COGNIS_AI_* configuration the backend is disabled
    and this returns a deterministic scaffold so the caller never breaks.
    """
    scaffold = {
        "name": name,
        "version": "0.1.0",
        "description": description.strip()[:200],
        "images": [],
        "charts": [],
        "manifests": [],
        "files": [],
        "_ai": "disabled — set COGNIS_AI_BACKEND to enable LLM drafting",
    }

    backend = _load_ai_backend()
    if backend is None or not backend.is_enabled() or not backend.health():
        return scaffold

    prompt = (
        "You are an air-gap delivery engineer. Given an app description, output "
        "ONLY a JSON object with keys: name, version, description, images "
        "(array of image refs), charts (array of {name, repo, version}), "
        "manifests (array of file paths), files (array of file paths). "
        "Infer realistic container images and Helm charts. No prose.\n\n"
        f"APP DESCRIPTION:\n{description}\n"
    )
    try:
        content = backend._chat(  # reuse the shared chat transport
            "Return strict JSON only. No markdown, no commentary.", prompt)
    except Exception:
        return scaffold
    parsed = _extract_json_object(content or "")
    if not isinstance(parsed, dict):
        return scaffold
    # Merge over scaffold, keeping the four artifact arrays present.
    for k in ("name", "version", "description", "images", "charts",
              "manifests", "files"):
        if k in parsed:
            scaffold[k] = parsed[k]
    scaffold["_ai"] = "drafted by local fleet"
    return scaffold


def _load_ai_backend():
    """Best-effort import of the suite's shared AI backend; None if unavailable."""
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "..", "..", "_shared", "cognis_ai_backend.py"),
        os.path.join(here, "_cognis_ai_backend.py"),
    ]
    for cand in candidates:
        cand = os.path.abspath(cand)
        if os.path.isfile(cand):
            try:
                spec = importlib.util.spec_from_file_location(
                    "cognis_ai_backend", cand)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore[union-attr]
                return mod.CognisAIBackend()
            except Exception:
                return None
    return None


def _extract_json_object(text: str) -> Any:
    text = text.strip()
    # Strip code fences if present.
    if "```" in text:
        import re
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None
