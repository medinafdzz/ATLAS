"""Append-only SQLite snapshot persistence and schema validation."""
import json
import os
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
    endpoints = set()
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
            endpoints.add((host["id"], check["id"]))
            if check.get("status") not in ("ok", "fail", "unknown", "drift") or not isinstance(check.get("required"), bool) or check.get("kind") not in ("file", "process", "executable", "symlink", "tcp"):
                raise ValueError("invalid check fields")
            for key in ("expected", "detail"):
                if check.get(key) is not None and (not isinstance(check[key], str) or len(check[key]) > 1024):
                    raise ValueError("invalid check field")
            if check.get("observed") is not None and (not isinstance(check["observed"], (str, int, float)) or len(str(check["observed"])) > 1024):
                raise ValueError("invalid observed value")

    deps = data.get("dependencies", [])
    if not isinstance(deps, list) or len(deps) > 2000:
        raise ValueError("invalid dependencies")
    seen = set()
    for dep in deps:
        if not isinstance(dep, dict) or set(dep) != {"source_host", "source_check", "target_host", "target_check", "kind"} or dep["kind"] != "requires":
            raise ValueError("invalid dependency")
        src = dep["source_host"], dep["source_check"]
        dst = dep["target_host"], dep["target_check"]
        if src not in endpoints or dst not in endpoints or src == dst or (src, dst) in seen:
            raise ValueError("invalid dependency endpoint")
        seen.add((src, dst))

class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, environment TEXT NOT NULL, collected_at REAL NOT NULL, payload TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS snapshots_env ON snapshots(environment,id DESC)")
            db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, environment TEXT NOT NULL, host TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL, level TEXT NOT NULL, occurred_at REAL NOT NULL, summary TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS events_env ON events(environment,occurred_at DESC)")

    def _db(self):
        return sqlite3.connect(self.path, timeout=10)

    def add(self, snapshot):
        validate_snapshot(snapshot)
        with self._db() as db:
            row = db.execute("INSERT INTO snapshots(environment,collected_at,payload) VALUES(?,?,?)",
                             (snapshot["environment"], snapshot["captured_at"], json.dumps(snapshot)))
            return row.lastrowid

    def backup(self, output):
        """Create verified, consistent SQLite backup without overwriting files."""
        target = str(output)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with self._db() as source, sqlite3.connect(target, timeout=10) as destination:
                source.backup(destination)
                if destination.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("backup failed integrity check")
            return target
        except BaseException:
            os.unlink(target)
            raise

    def add_events(self, events):
        from .events import validate_event
        if not isinstance(events, list) or not 1 <= len(events) <= 100:
            raise ValueError("expected 1..100 events")
        for event in events:
            validate_event(event)
        with self._db() as db:
            db.executemany("INSERT INTO events(environment,host,source,kind,level,occurred_at,summary) VALUES(?,?,?,?,?,?,?)",
                [(e["environment"], e["host"], e["source"], e["kind"], e["level"], e["occurred_at"], e["summary"]) for e in events])
        return len(events)

    def events(self, environment, limit=100):
        with self._db() as db:
            rows = db.execute("SELECT id,environment,host,source,kind,level,occurred_at,summary FROM events WHERE environment=? ORDER BY occurred_at DESC,id DESC LIMIT ?", (environment, min(limit,100))).fetchall()
        keys = ("id","environment","host","source","kind","level","occurred_at","summary")
        return [dict(zip(keys,row)) for row in rows]

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
        from .events import correlate
        events = self.events(environment)
        return {"snapshot_id": rows[0][0], "report": report, "diff": changes, "events": events,
                "incidents": correlate(diagnose(report, changes), events, newest["captured_at"])}
