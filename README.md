# ATLAS

ATLAS is a free, self-hosted infrastructure assurance toolkit. It collects bounded, read-only observations from an explicitly configured host inventory, checks expected state, tracks configuration changes and presents evidence-backed findings in a private dashboard.

ATLAS is designed for development, staging and integration systems. **It is not an autonomous remediation agent and is not certified for operational safety-critical environments.**

## Features

- Host inventory with explicit local and SSH targets (no subnet scans or automatic propagation).
- Linux process checks via `/proc`, without collecting command-line arguments.
- Executable availability, SHA-256 file checks (up to 16 MiB each), symlink integrity and opt-in TCP checks.
- Readiness states: `ready`, `blocked`, `unknown`. Unknown and stale snapshots never count as current success.
- Explicitly declared dependency relationships between checks across hosts.
- Expected-state deviation and change detection between successive snapshots.
- Evidence-backed incident findings; root cause is not inferred without proof.
- Append-only local SQLite history, private API and browser dashboard.
- Offline operation with no cloud or AI requirement.

## Installation

Central app: Python 3.9+. Optional remote Linux targets need Python 3.6+ and SSH permissions for the approved observer user.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
atlas capture examples/lab.json --output snapshot.json
atlas inspect snapshot.json
atlas import snapshot.json --db atlas.sqlite3
export ATLAS_DB=atlas.sqlite3
export ATLAS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
atlas serve
```

Open http://127.0.0.1:8000, enter the token configured in the shell and select the environment. The browser keeps the token in tab memory only. `atlas inspect` exits with code 2 for a blocked or unknown environment.

Docker Compose is also supported: define a strong `ATLAS_API_TOKEN` and execute `docker compose up --build -d`. The bundled Compose file binds to **localhost only**. For shared network access, deploy a company-approved TLS proxy and identity gateway.

## Inventory

An environment is a JSON manifest with `schema_version: 1`, a named environment and explicitly listed hosts.

```json
{
  "schema_version": 1,
  "environment": "staging",
  "hosts": [
    {
      "id": "node-a",
      "transport": "local",
      "role": "web",
      "checks": [
        {"id": "python", "kind": "executable", "name": "python3", "required": true},
        {"id": "config", "kind": "file", "name": "/etc/hosts", "required": false},
        {"id": "web", "kind": "process", "name": "nginx", "required": true}
      ]
    }
  ]
}
```

Check kinds:

| Kind | `name` | Observation |
| --- | --- | --- |
| `executable` | executable name | executable path from PATH |
| `process` | exact Linux process name | count from `/proc/*/comm` |
| `file` | absolute path | `sha256:<hex>` |
| `symlink` | absolute path | target and integrity |
| `tcp` | hostname:port | one-second TCP connection probe |

An optional `expected` field compares against the observed value; mismatches result in `drift`. Do not put secrets into inventory or the snapshot database.

### Explicit remote SSH collection

For an authorized remote target, set `transport` to `ssh`, with `address`, `user` and optional `port`. Remote collection is disabled unless the operator runs:

```bash
atlas capture approved-inventory.json --output snapshot.json --allow-ssh
```

Remote SSH uses batch mode and strict host-key verification. The target must be in the approved inventory and known-hosts configuration. A bounded Python probe executes non-persistently on the target. ATLAS does not elevate privileges, reuse discovered credentials, scan networks, deploy itself or modify remote files.

## Dependencies

A manifest can define optional `dependencies` with `source_host`, `source_check`, `target_host`, `target_check` and `kind: requires`. All endpoints must be declared in the manifest. A missing or failed target affects the dependent host's readiness while preserving the underlying observation. Dependencies are configured relationships; ATLAS does not claim to infer a network topology automatically.

## Commands

| Command | Purpose |
| --- | --- |
| `atlas capture MANIFEST --output FILE` | Capture local checks; remote targets remain unknown |
| `atlas capture MANIFEST --output FILE --allow-ssh` | Also query explicitly configured SSH hosts |
| `atlas inspect SNAPSHOT` | Print readiness and check results |
| `atlas watch MANIFEST --db FILE --interval 300` | Repeat bounded captures (remote SSH stays disabled unless explicitly enabled) |
| `atlas import SNAPSHOT --db FILE` | Append snapshot to SQLite |
| `atlas serve --host 127.0.0.1 --port 8000` | Run the private dashboard |
| `atlas --help` | CLI usage |

The API requires `Authorization: Bearer <ATLAS_API_TOKEN>`. Routes: `GET /healthz`, `GET /api/environments`, `GET /api/environments/{environment}/latest`, `GET /api/environments/{environment}/snapshots`, `POST /api/snapshots`.

## Offline installation on Linux

The optional **offline-package** GitHub Actions workflow builds an installation bundle containing a Python 3.12 Linux x86-64 wheelhouse, example inventory, systemd service templates and the README. It tests installation using `pip --no-index`. Download and verify the bundle through an approved software distribution channel before using it in an organization.

Create an unprivileged `atlas` system account and directories `/opt/atlas/venv` and `/var/lib/atlas`, restricted to that account. Install with `pip install --no-index --find-links wheelhouse atlas-infrastructure`. Create `/etc/atlas/manifest.json` from your approved host inventory and a protected `/etc/atlas/atlas.env` containing `ATLAS_API_TOKEN` and `ATLAS_DB=/var/lib/atlas/atlas.sqlite3`. Review the `deploy/systemd` templates with the server administrator before installing them; the default observer does not enable remote SSH. Protect the dashboard behind a company-approved TLS identity gateway when accessed beyond localhost.

The package is **not** a universal installer for RHEL/Python 3.6: ATLAS Central needs Python 3.9 or newer. The remote read-only probe is Python 3.6-compatible and can be used against explicitly authorized legacy targets.

## Operations and limitations

- Install with least privileges and restrict database and inventory file permissions.
- Snapshots may contain confidential hostnames, paths and service states. They remain on the local filesystem until explicitly deleted; there is no automatic retention policy.
- Back up the SQLite database using a consistent backup method and validate restores in a test environment.
- Remote collection is sequential and can be disabled entirely.
- The server does not provide SSO, enterprise RBAC, autonomous scheduling, dependency-graph inference, production HA, LLM diagnosis or vendor-specific integrations.
- No automatic changes or remediation actions are supported. Every finding distinguishes observed facts from root-cause hypotheses.
- Test a replica before using ATLAS in critical or regulated environments.

## Development and tests

```bash
python -m pip install -e '.[dev]'
pytest -q
python -m compileall -q src/atlas
```

The test suite covers collection, validation, readiness, drift, persistence, API auth and SSH opt-in. See `examples/lab.json` for a minimal local environment.

## License

Apache-2.0; see [LICENSE](LICENSE). Report vulnerabilities without attaching production logs, private configuration or credentials.
