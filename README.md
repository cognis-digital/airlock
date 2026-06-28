# airlock

**Declarative air-gapped software delivery.** Bundle OCI images, Helm charts,
raw Kubernetes manifests, and arbitrary files into **one portable, verifiable
archive** that you can carry across an air-gap and replay into a disconnected
cluster.

Part of the **Cognis Neural Suite**. Standard-library-only Python — no pip
dependencies, no network required for the offline path.

---


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ airlock-emit --version
airlock 0.1.0
```

```console
$ airlock-emit --help
usage: airlock [-h] [--version]
               {create,inspect,verify,deploy,draft,extract,diff,mcp} ...

Declarative air-gapped software delivery — bundle OCI images, Helm charts, and
manifests into one verifiable archive for disconnected clusters.

positional arguments:
  {create,inspect,verify,deploy,draft,extract,diff,mcp}
    create              Resolve a manifest into a portable bundle.tar
    inspect             List a bundle's contents, sizes, and hashes.
    verify              Recompute and check every artifact's sha256.
    deploy              Plan/seed a disconnected cluster from a bundle.
    draft               Draft an airlock manifest from plain English (--ai).
    extract             Unpack a bundle to a directory (verified).
    diff                Diff two bundles by their artifact index.
    mcp                 Run as an MCP server (stdio JSON-RPC).

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

> Blocks above are real `airlock` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"findings": [
    {
        "id": "1234567890",
        "title": "Suspicious Network Traffic",
        "description": "Possible malicious activity detected on port 80",
        "created_at": "2023-02-20T14:30:00Z",
        "updated_at": "2023-02-20T14:30:01Z"
    },
    {
        "id": "2345678901",
        "title": "Unusual File Access",
        "description": "User accessed a file with suspicious permissions",
        "created_at": "2023-02-21T10:45:00Z",
        "updated_at": "2023-02-21T10:45:01Z"
    }
]
}
```

<!-- cognis:example:end -->

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

## Interoperability

`airlock` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `airlock`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

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

## Usage — step by step

`airlock` bundles OCI images, Helm charts, and manifests into one verifiable archive you can carry to a disconnected cluster.

1. **Install** (pure stdlib, Python 3.10+):
   ```bash
   pip install "git+https://github.com/cognis-digital/airlock.git"
   ```
2. **Create a bundle** from an `airlock.yaml` manifest (`--no-pull` records intent without shelling out to docker/helm):
   ```bash
   airlock create airlock.yaml -o bundle.tar
   ```
3. **Inspect and verify** the archive — contents, sizes, hashes, and a recompute of every artifact's sha256 against the Merkle root:
   ```bash
   airlock inspect bundle.tar
   airlock verify  bundle.tar
   ```
4. **Deploy on the far side** — preview the docker/helm/kubectl commands first, then run against the in-cluster registry/namespace:
   ```bash
   airlock deploy bundle.tar --dry-run
   airlock deploy bundle.tar --registry localhost:5000 --namespace prod
   ```
5. **Automate** — gate CI on `verify`, or diff two bundles by their artifact index across releases:
   ```bash
   airlock verify bundle.tar --format json && airlock diff old.tar bundle.tar
   ```
   Or run it as a local MCP server (stdio JSON-RPC): `airlock mcp`.
