# airlock

**Declarative air-gapped software delivery.** Bundle OCI images, Helm charts,
raw Kubernetes manifests, and arbitrary files into **one portable, verifiable
archive** that you can carry across an air-gap and replay into a disconnected
cluster.

Part of the **Cognis Neural Suite**. Standard-library-only Python — no pip
dependencies, no network required for the offline path.

---

## Why

Disconnected and classified environments cannot `docker pull` or `helm repo
add` at deploy time. airlock lets you *declare once* everything an app needs,
gather it into a single `bundle.tar` on a connected machine, carry that one
file across the gap, **prove its integrity**, and then seed the disconnected
cluster from it.

## The manifest

Write `airlock.yaml` (a small, well-defined YAML subset) or `airlock.json`:

```yaml
name: hello-edge
version: 1.2.0
description: A minimal web app shipped fully offline.

images:
  - nginx:1.27-alpine
  - ref: ghcr.io/cognis-digital/hello-edge:1.2.0

charts:
  - name: redis
    repo: https://charts.example.com/stable
    version: 19.6.4
    release: cache

manifests:
  - manifests/deployment.yaml
  - manifests/service.yaml

files:
  - sample-files/config.env
  - sample-files/runbook.md
```

## Commands

```bash
# Gather declared artifacts into one verifiable archive.
python -m airlock create airlock.yaml -o bundle.tar

# List contents, sizes, and sha256 (table or --format json).
python -m airlock inspect bundle.tar

# Recompute every artifact hash + the Merkle root; non-zero on tamper.
python -m airlock verify bundle.tar

# Print the exact docker / helm / kubectl plan (run for real without --dry-run).
python -m airlock deploy bundle.tar --dry-run

# Run as a local MCP server (stdio JSON-RPC).
python -m airlock mcp
```

`create` shells out to `docker`/`oras`/`helm` when they are on `PATH` to pull
real images and charts. When they are absent (the common offline-demo case),
airlock **records the intent** for those artifacts and still packs every local
manifest and file for real — so the bundle is always structurally valid and
verifiable.

## What's in a bundle

```
bundle.tar
├── bundle.json          # resolved manifest + per-artifact index (sha256, size, status)
├── checksums.txt        # "<sha256>  <arcname>" for every artifact
├── attestation.json     # detached integrity statement (Merkle root + manifest hash)
└── artifacts/
    ├── images/          # docker-saved tars (or recorded intent)
    ├── charts/          # helm-pulled tgz (or recorded intent)
    ├── manifests/       # raw k8s YAML/JSON
    └── files/           # arbitrary blobs
```

## What sets airlock apart

- **Integrity by default.** Every artifact carries a sha256; the bundle carries
  a Merkle root over all of them plus a **detached attestation** so tampering
  anywhere in the tree is detectable. `verify` is a real tamper check.
- **MCP-native.** Ships an MCP server exposing `create`/`inspect`/`verify`, so
  agentic tools can build and audit air-gap bundles directly.
- **Optional AI drafting (`draft --ai`, default OFF).** Describe an app in plain
  English and have the **local Cognis fleet** draft an `airlock.yaml` for you.
  With no `COGNIS_AI_*` configuration the hook is disabled and emits a
  deterministic scaffold — nothing leaves your machine.
- **Zero dependencies.** Pure Python standard library.

## Demo

See [`demos/01-basic`](demos/01-basic/SCENARIO.md) for an end-to-end walk-through.

```bash
python -m airlock create demos/01-basic/airlock.yaml -o /tmp/bundle.tar
python -m airlock inspect /tmp/bundle.tar
python -m airlock verify  /tmp/bundle.tar
python -m airlock deploy  /tmp/bundle.tar --dry-run
```

## Tests

```bash
python -m pytest -q       # or: python -m unittest discover -s tests
```

## License

Cognis Open Collaboration License (COCL) 1.0 — see [`LICENSE`](LICENSE).
© 2026 Cognis Digital LLC.

This is original Cognis work. airlock is conceptually a declarative air-gap
packager but contains no third-party code, names, or branding.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** AI & ML  ·  **JTF MERIDIAN division:** ATHENA-PRIME · SAGE

**Topics:** `cognis` `ai` `llm` `machine-learning`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->
