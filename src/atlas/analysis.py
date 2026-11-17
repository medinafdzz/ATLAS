"""Deterministic readiness, change detection and evidence-driven findings."""
import time
def evaluate(snapshot, max_age_seconds=900):
    stale = time.time() - snapshot["captured_at"] > max_age_seconds
    totals = {"ok": 0, "fail": 0, "unknown": 0, "drift": 0}
    hosts = []
    for host in snapshot["hosts"]:
        checks = []
        for original in host["checks"]:
            check = dict(original)
            status = check.get("status", "unknown")
            expected = check.get("expected")
            if status == "ok" and expected is not None and str(check.get("observed")) != expected:
                status = "drift"
            if status not in totals:
                status = "unknown"
            check["status"] = status
            totals[status] += 1
            checks.append(check)
        required = [c["status"] for c in checks if c.get("required", True)]
        status = "blocked" if any(s in ("fail", "drift") for s in required) else "unknown" if "unknown" in required else "ready"
        hosts.append({"id": host["id"], "role": host["role"], "status": status, "checks": checks})
    status_map = {(host["id"], c["id"]): c["status"] for host in hosts for c in host["checks"]}
    host_map = {host["id"]: host for host in hosts}
    dependencies = []
    for dep in snapshot.get("dependencies", []):
        src = dep["source_host"], dep["source_check"]
        dst = dep["target_host"], dep["target_check"]
        target_status = status_map.get(dst, "unknown")
        dependencies.append({**dep, "target_status": target_status})
        host = host_map.get(src[0])
        if host and target_status != "ok":
            host.setdefault("blocked_by", []).append({"check": src[1], "target_host": dst[0],
                                                       "target_check": dst[1], "target_status": target_status})
            if target_status in ("fail", "drift"):
                host["status"] = "blocked"
            elif host["status"] == "ready":
                host["status"] = "unknown"
    if stale:
        for host in hosts:
            host["status"] = "unknown"
            host["stale"] = True
    overall = "blocked" if any(h["status"] == "blocked" for h in hosts) else "unknown" if any(h["status"] == "unknown" for h in hosts) else "ready"
    return {"environment": snapshot["environment"], "status": overall, "captured_at": snapshot["captured_at"], "stale": stale, "totals": totals, "hosts": hosts, "dependencies": dependencies}

def diff(before, after):
    prev = {(h["id"], c["id"]): c for h in before["hosts"] for c in h["checks"]}
    curr = {(h["id"], c["id"]): c for h in after["hosts"] for c in h["checks"]}
    changes = []
    for key in sorted(set(prev) | set(curr)):
        old, new = prev.get(key), curr.get(key)
        if old is None or new is None or any(old.get(field) != new.get(field) for field in ("status", "observed", "detail")):
            changes.append({"host": key[0], "check": key[1], "before": old, "after": new})
    return {"environment": after["environment"], "changes": changes, "total": len(changes)}

def diagnose(report, changes=None):
    changed = {(c["host"], c["check"]) for c in (changes or {}).get("changes", [])}
    findings = []
    impact = {}
    for dep in report.get("dependencies", []):
        if dep.get("target_status") != "ok":
            key = dep["target_host"], dep["target_check"]
            impact[key] = impact.get(key, 0) + 1
    for host in report["hosts"]:
        for check in host["checks"]:
            if check["status"] in ("fail", "drift", "unknown"):
                changed_here = (host["id"], check["id"]) in changed
                dependents = impact.get((host["id"], check["id"]), 0)
                priority = (2 if check["status"] in ("fail", "drift") else 0) + (2 if changed_here else 0) + min(dependents * 2, 10)
                findings.append({"host": host["id"], "check": check["id"], "status": check["status"],
                                 "priority_score": priority, "dependent_checks": dependents,
                                 "finding": {"fail": "Resource unavailable", "drift": "Expected-state deviation",
                                             "unknown": "Insufficient evidence"}[check["status"]],
                                 "evidence": check.get("detail"), "expected": check.get("expected"),
                                 "observed": check.get("observed"), "recently_changed": changed_here,
                                 "conclusion": "stale evidence; refresh required" if report.get("stale") else "observation; root cause not established"})
    return sorted(findings, key=lambda item: (-item["priority_score"], item["host"], item["check"]))
