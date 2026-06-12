# airlock — Usage Guide

airlock packages everything a disconnected app needs — OCI images, Helm charts,
raw manifests, and files — into ONE verifiable `bundle.tar`, then replays it
into an air-gapped cluster.

## The manifest

```yaml
name: hello-edge
version: 1.2.0
images:
  - nginx:1.27-alpine
  - ref: ghcr.io/cognis-digital/hello-edge:1.2.0
charts:
  - {name: redis, repo: https://charts.example.com, version: 19.6.4, release: cache}
manifests:
  - manifests/deployment.yaml
files:
  - sample-files/config.env
```

## Commands

```bash
# Gather declared artifacts into one verifiable archive.
python -m airlock create airlock.yaml -o bundle.tar

# List contents, sizes, sha256.
python -m airlock inspect bundle.tar

# Recompute every artifact hash + Merkle root; non-zero on tamper.
python -m airlock verify bundle.tar

# Unpack a bundle to a directory — verified first, path-traversal-safe.
python -m airlock extract bundle.tar ./unpacked
python -m airlock extract bundle.tar ./unpacked --no-verify   # skip the check

# Diff two bundles by their artifact index (added / removed / changed).
python -m airlock diff old-bundle.tar new-bundle.tar

# Print the exact docker/helm/kubectl seed plan (run for real without --dry-run).
python -m airlock deploy bundle.tar --dry-run

# Draft a manifest from plain English (local-fleet AI, default OFF).
python -m airlock draft "a redis-backed web app" --name myapp

# MCP server (create / inspect / verify).
python -m airlock mcp
```

## What's in a bundle

```
bundle.tar
├── bundle.json          # resolved manifest + per-artifact index (sha256, size, status)
├── checksums.txt        # "<sha256>  <arcname>" for every artifact
├── attestation.json     # detached integrity statement (Merkle root + manifest hash)
└── artifacts/{images,charts,manifests,files}/...
```

## Safe extract

`extract` runs `verify` first by default and **refuses** to unpack a tampered
bundle. It also rejects any archive member that would escape the destination
directory (path-traversal / zip-slip), so it is safe to run on bundles from an
untrusted courier.

## diff for promotions

`diff` compares two bundles' artifact name → sha256 maps — ideal for reviewing
exactly what changed between a staging bundle and the production one before you
carry it across the gap:

```bash
python -m airlock diff staging.tar prod-candidate.tar
# + new-config.env
# ~ artifacts/images/app.tar  (content changed)
```

## CI recipe

```bash
python -m airlock create airlock.yaml -o bundle.tar
python -m airlock verify bundle.tar || exit 1
python -m airlock diff last-shipped.tar bundle.tar     # review the delta
```
