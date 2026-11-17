"""Bounded read-only probe compatible with Python 3.6+."""
from __future__ import print_function
import hashlib
import json
import os
import shutil
import socket
import sys
import time

MAX_FILE_BYTES = 16 * 1024 * 1024

def probe(check):
    kind = check["kind"]
    name = check["name"]
    try:
        if kind == "executable":
            found = shutil.which(name)
            return dict(status="ok" if found else "fail", observed=found, detail="executable lookup")
        if kind == "process":
            if not os.path.isdir("/proc"):
                return dict(status="unknown", observed=None, detail="procfs unavailable")
            count = 0
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open("/proc/{}/comm".format(pid)) as stream:
                        if stream.read().strip() == name:
                            count += 1
                except (IOError, OSError):
                    continue
            return dict(status="ok" if count else "fail", observed=count, detail="exact process name")
        if kind == "file":
            if not os.path.isfile(name):
                return dict(status="fail", observed=None, detail="file missing")
            if os.path.getsize(name) > MAX_FILE_BYTES:
                return dict(status="unknown", observed=None, detail="file exceeds scan budget")
            digest = hashlib.sha256()
            with open(name, "rb") as stream:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    digest.update(block)
            return dict(status="ok", observed="sha256:" + digest.hexdigest(), detail="file digest")
        if kind == "symlink":
            if not os.path.islink(name):
                return dict(status="fail", observed=None, detail="symlink missing")
            target = os.readlink(name)
            valid = os.path.exists(name)
            return dict(status="ok" if valid else "fail", observed=target, detail="target exists" if valid else "broken link")
        if kind == "tcp":
            host, port = name.rsplit(":", 1)
            connection = socket.create_connection((host, int(port)), timeout=1.0)
            connection.close()
            return dict(status="ok", observed="connected", detail="tcp connection succeeded")
    except (IOError, OSError, ValueError, socket.error) as exc:
        return dict(status="unknown", observed=None, detail=type(exc).__name__)
    return dict(status="unknown", observed=None, detail="unsupported check")

def capture(checks):
    results = []
    for check in checks[:100]:
        result = probe(check)
        result.update(id=check["id"], kind=check["kind"], required=check.get("required", True), expected=check.get("expected"))
        results.append(result)
    return dict(observed_at=time.time(), checks=results)

if __name__ == "__main__":
    if len(sys.argv) != 2 or len(sys.argv[1]) > 65536:
        sys.exit("usage: python agent.py JSON_CHECKS")
    try:
        checks = json.loads(sys.argv[1])
        if not isinstance(checks, list) or len(checks) > 100:
            raise ValueError("invalid checks")
        allowed = set(("id", "kind", "name", "required", "expected"))
        kinds = set(("executable", "process", "file", "symlink", "tcp"))
        for check in checks:
            if not isinstance(check, dict) or set(check) - allowed or check.get("kind") not in kinds or not isinstance(check.get("name"), str):
                raise ValueError("invalid check")
        print(json.dumps(capture(checks), sort_keys=True))
    except (ValueError, TypeError) as exc:
        sys.exit("invalid request: " + str(exc))
