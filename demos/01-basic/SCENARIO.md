# Demo 01 — Bundling an app for a disconnected cluster

This scenario takes `airlock.yaml`, a declarative manifest for a small web app,
and produces ONE portable, verifiable `bundle.tar` you can carry across an
air-gap.

## Run it

```bash
# 1. Gather everything the manifest declares into one archive.
python -m airlock create demos/01-basic/airlock.yaml -o /tmp/bundle.tar

# 2. See exactly what shipped — sizes, sha256, the bundle manifest.
python -m airlock inspect /tmp/bundle.tar

# 3. Prove integrity (recompute every hash + the Merkle root).
python -m airlock verify /tmp/bundle.tar

# 4. Review the commands that would seed a disconnected cluster.
python -m airlock deploy /tmp/bundle.tar --dry-run
```

## What you get

| Stage    | Result                                                              |
|----------|--------------------------------------------------------------------|
| create   | `bundle.tar` with `bundle.json`, `checksums.txt`, `attestation.json` and the gathered artifacts under `artifacts/` |
| inspect  | A table of every artifact with its kind, status, size, and sha256  |
| verify   | PASS only if every artifact hash and the Merkle root still match   |
| deploy   | The ordered `docker load/tag/push`, `helm install`, `kubectl apply` plan |

If no `docker`/`helm`/`oras` are on PATH (the offline-demo case), images and
charts are recorded as *intent* and the local manifests + files are packed
for real — so the bundle is always structurally valid and verifiable.

## Tamper check

`verify` is a tamper detector. If any byte of a packed artifact changes, the
recomputed sha256 (and the Merkle root) will no longer match the bundle
manifest, and `verify` exits non-zero.
