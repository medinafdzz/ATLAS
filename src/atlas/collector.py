"""Inventory-scoped collection with strict SSH host keys and opt-in."""
import json
import pathlib
import shlex
import subprocess
import time
from .agent import capture
from .models import Manifest

def collect(manifest: Manifest, allow_ssh=False):
    code = pathlib.Path(__file__).with_name("agent.py").read_text(encoding="utf-8")
    hosts = []
    for host in manifest.hosts:
        checks = [check.model_dump() for check in host.checks]
        if host.transport == "local":
            sample = capture(checks)
        elif not allow_ssh:
            sample = {"observed_at": time.time(), "checks": [
                {"id": c.id, "kind": c.kind, "required": c.required, "expected": c.expected,
                 "status": "unknown", "observed": None, "detail": "remote access disabled"} for c in host.checks]}
        else:
            payload = json.dumps(checks, separators=(",", ":"))
            remote_command = "python3 -c {} {}".format(shlex.quote(code), shlex.quote(payload))
            args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "ConnectTimeout=5", "-o", "NumberOfPasswordPrompts=0",
                    "-p", str(host.port), "--", "{}@{}".format(host.user, host.address), remote_command]
            try:
                response = subprocess.run(args, capture_output=True, text=True, timeout=20, check=True)
                sample = json.loads(response.stdout)
                if not isinstance(sample, dict) or not isinstance(sample.get("checks"), list):
                    raise ValueError("invalid SSH result")
                indexed = {c["id"]: c for c in sample["checks"]}
                if len(indexed) != len(host.checks) or set(indexed) != {c.id for c in host.checks}:
                    raise ValueError("unexpected remote checks")
                sample["checks"] = [indexed[c.id] for c in host.checks]
            except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                sample = {"observed_at": time.time(), "checks": [
                    {"id": c.id, "kind": c.kind, "required": c.required, "expected": c.expected,
                     "status": "unknown", "observed": None, "detail": "remote failure: " + type(exc).__name__} for c in host.checks]}
        hosts.append({"id": host.id, "role": host.role, "transport": host.transport,
                      "observed_at": sample["observed_at"], "checks": sample["checks"]})
    return {"schema_version": 1, "environment": manifest.environment, "captured_at": time.time(), "hosts": hosts,
            "dependencies": [dep.model_dump() for dep in manifest.dependencies]}
