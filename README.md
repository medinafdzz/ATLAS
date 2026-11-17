# ATLAS

ATLAS is a self-hosted, read-only infrastructure assurance toolkit. It collects evidence from an explicit host inventory, evaluates readiness, tracks configuration drift and presents findings in a private dashboard.

The initial release supports offline captures, Linux checks, optional approved SSH observations, SQLite storage and a token-protected FastAPI dashboard. It is intended for controlled development and integration environments, not safety-critical operational systems. No automatic repair, network propagation or credential discovery.

## Quick start

```bash
python -m pip install -e '.[dev]'
atlas capture examples/lab.json --output snapshot.json
atlas inspect snapshot.json
atlas import snapshot.json --db atlas.sqlite3
export ATLAS_DB=atlas.sqlite3
export ATLAS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
atlas serve
```

Open http://127.0.0.1:8000 and enter the API token. Remote SSH access is **off by default** and requires `--allow-ssh` with an explicitly approved manifest and pre-existing host keys. Never point ATLAS at an unapproved corporate or production environment.

## Verification

`pytest -q` after installing the development extras. See the package CLI with `atlas --help`.

## Status

Version 0.1.0 is a functional laboratory baseline, not an enterprise-certified monitoring product. It does not yet provide autonomous scheduling, topology inference, SSO, HA or commercial integrations. These capabilities require further implementation and validation.

Apache-2.0 licensed. See `LICENSE`.