"""Append-only SQLite snapshot persistence and schema validation."""
import json
import re
import sqlite3
import time
from pathlib import Path
from .analysis import evaluate, diff, diagnose

IDENT = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

def validate_snapshot(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported snapshot schema")
    if not isinstance(data.get("environment"), str) or not IDENT.fullmatch(data["environment"]):
        raise ValueError("invalid environment")
    stamp = data.get("captured_at")
    if not isinstance(stamp, (int, float)) or not 0 < stamp <= time.time() + 300:
        raise ValueError("invalid capture time")
    hosts = data.get("hosts")
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 500:
        raise ValueError("invalid hosts")
    seen_hosts = set()
    for host in hosts:
        if not isinstance(host, dict) or not isinstance(host.get("id"), str) or not IDENT.fullmatch(host["id"]) or host["id"] in seen_hosts:
            raise ValueError("invalid or duplicate host")
        seen_hosts.add(host["id"])
        if not isinstance(host.get("role"), str) or len(host["role"]) > 128:
            raise ValueError("invalid role")
        checks = host.get("checks")
        if not isinstance(checks, list) or not 1 <= len(checks) <= 100:
            raise ValueError("invalid checks")
        seen_checks = set()
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("id"), str) or not IDENT.fullmatch(check["id"]) or check["id"] in seen_checks:
                raise ValueError("invalid or duplicate check")
            seen_checks.add(check["id"])
            if check.get("status") not in ("ok", "fail", "unknown", "drift") or not isinstance(check.get("required"), bool) or check.get("kind") not in ("file", "process", "executable", "symlink", "tcp"):
                raise ValueError("invalid check fields")
            for key in ("expected", "detail"):
                if check.get(key) is not None and (not isinstance(check[key], str) or len(check[key]) > 1024):
                    raise ValueError("invalid check field")
            if check.get("observed") is not None and (not isinstance(check["observed"], (str, int, float)) or len(str(check["observed"])) > 1024):
                raise ValueError("invalid observed value")

class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, environment TEXT NOT NULL, collected_at REAL NOT NULL, payload TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS snapshots_env ON snapshots(environment,id DESC)")

    def _db(self):
        return sqlite3.connect(self.path, timeout=10)

    def add(self, snapshot):
        validate_snapshot(snapshot)
        with self._db() as db:
            row = db.execute("INSERT INTO snapshots(environment,collected_at,payload) VALUES(?,?,?)",
                             (snapshot["environment"], snapshot["captured_at"], json.dumps(snapshot)))
            return row.lastrowid

    def environments(self):
        with self._db() as db:
            return [{"environment": row[0], "snapshots": row[1], "last_seen": row[2]} for row in db.execute(
                "SELECT environment,COUNT(*),MAX(collected_at) FROM snapshots GROUP BY environment ORDER BY environment")]

    def list_snapshots(self, environment):
        with self._db() as db:
            return [{"id": row[0], "captured_at": row[1]} for row in db.execute(
                "SELECT id,collected_at FROM snapshots WHERE environment=? ORDER BY id DESC LIMIT 30", (environment,))]

    def latest(self, environment):
        with self._db() as db:
            rows = db.execute("SELECT id,payload FROM snapshots WHERE environment=? ORDER BY id DESC LIMIT 2", (environment,)).fetchall()
        if not rows:
            return None
        newest = json.loads(rows[0][1])
        previous = json.loads(rows[1][1]) if len(rows) > 1 else None
        changes = diff(previous, newest) if previous else {"environment": environment, "changes": [], "total": 0}
        report = evaluate(newest)
        return {"snapshot_id": rows[0][0], "report": report, "diff": changes, "incidents": diagnose(report, changes)}
