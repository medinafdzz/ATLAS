# ATLAS Portable: offline Linux deployment

The portable package is a one-shot, read-only infrastructure inspection tool.
It requires Linux with Python 3.6 or newer and does not require pip, Docker, cloud
access, root privileges, a database or an installed background service.

Run `./run-atlas.sh` from an authorized integration/lab machine, after
verifying the archive checksum through your normal software approval process.

The command creates `results/capture-TIMESTAMP-PID.json`, a static HTML
report and `results/latest.json`. The next run compares captured values.
The sample policy checks only local Python, shell and `/etc/os-release`.

For a custom, approved list of checks, use:

```sh
./run-atlas.sh --manifest /path/to/approved-manifest.json
```

To write output outside the bundle, set `ATLAS_OUTPUT_DIR`.

Exit statuses: 0 all required checks ready; 2 blocked or unknown; 1
invalid manifest or I/O failure. An inaccessible target is unknown, not healthy.

Remote access is **disabled by default**. To query any remote host, list it
explicitly in the manifest, supply a dedicated least-privilege account,
verify its SSH host key separately, and run with `--allow-ssh`. The
probe is non-persistent and does not install anything remotely.

Reports can include confidential infrastructure metadata. Never upload real
reports, manifests, credentials or logs to a public repository. Only use
approved networks, servers, paths and tests. This utility is not certified
for safety-critical operational systems.

Python 3.6 compatibility has a static syntax check in CI; runtime execution
on the exact target RHEL version must still be tested before final acceptance.
