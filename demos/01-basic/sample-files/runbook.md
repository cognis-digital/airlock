# hello-edge — air-gap runbook

1. Carry `bundle.tar` to the disconnected environment on approved media.
2. `airlock verify bundle.tar` — confirm integrity before trusting it.
3. `airlock deploy bundle.tar --dry-run` — review the exact commands.
4. Run the deploy for real once the in-cluster registry is reachable.
