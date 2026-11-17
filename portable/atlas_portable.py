#!/usr/bin/env python3
"""Dependency-free, read-only report generator for Python 3.6+ Linux."""
from __future__ import print_function
import argparse
import html
import json
import os
import re
import shlex
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
from atlas.agent import capture

ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
HOST = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
KINDS = set(("executable", "process", "file", "symlink", "tcp"))

def validate(inventory):
    if not isinstance(inventory, dict) or inventory.get("schema_version") != 1:
        raise ValueError("unsupported manifest")
    if not isinstance(inventory.get("environment"), str) or not ID.fullmatch(inventory["environment"]):
        raise ValueError("invalid environment")
    hosts = inventory.get("hosts")
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 500:
        raise ValueError("invalid hosts")
    seen = set()
    endpoints = set()
    for host in hosts:
        if not isinstance(host, dict) or not isinstance(host.get("id"), str) or not ID.fullmatch(host["id"]) or host["id"] in seen:
            raise ValueError("invalid or duplicate host")
        seen.add(host["id"])
        if host.get("transport") not in ("local", "ssh"):
            raise ValueError("invalid transport")
        if host["transport"] == "ssh":
            if not isinstance(host.get("address"), str) or not HOST.fullmatch(host["address"]) or not isinstance(host.get("user"), str) or not USER.fullmatch(host["user"]):
                raise ValueError("invalid SSH target")
            if not isinstance(host.get("port", 22), int) or not 1 <= host.get("port", 22) <= 65535:
                raise ValueError("invalid port")
        elif host.get("user") or host.get("address"):
            raise ValueError("invalid local target")
        checks = host.get("checks")
        if not isinstance(checks, list) or not 1 <= len(checks) <= 100:
            raise ValueError("invalid check list")
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("id"), str) or not ID.fullmatch(check["id"]) or check.get("kind") not in KINDS or not isinstance(check.get("name"), str):
                raise ValueError("invalid check")
            name = check["name"]
            if not 1 <= len(name) <= 512 or any(c in name for c in "\x00\r\n"):
                raise ValueError("unsafe check name")
            if check["kind"] in ("file", "symlink") and not name.startswith("/"):
                raise ValueError("absolute path required")
            if check["kind"] == "tcp":
                target, sep, port = name.rpartition(":")
                if not sep or not target or not port.isdigit() or not 1 <= int(port) <= 65535:
                    raise ValueError("invalid TCP check")
            key = (host["id"], check["id"])
            if key in endpoints:
                raise ValueError("duplicate check")
            endpoints.add(key)
    dependencies = inventory.get("dependencies", [])
    if not isinstance(dependencies, list) or len(dependencies) > 2000:
        raise ValueError("invalid dependencies")
    pairs = set()
    for dep in dependencies:
        if not isinstance(dep, dict) or dep.get("kind", "requires") != "requires":
            raise ValueError("invalid dependency")
        src = (dep.get("source_host"), dep.get("source_check"))
        dst = (dep.get("target_host"), dep.get("target_check"))
        if src not in endpoints or dst not in endpoints or src == dst or (src, dst) in pairs:
            raise ValueError("invalid dependency endpoints")
        pairs.add((src, dst))
    return inventory

def missing(check, message):
    return {"id": check["id"], "kind": check["kind"], "required": check.get("required", True),
            "expected": check.get("expected"), "status": "unknown", "observed": None, "detail": message}

def observe(inventory, allow_ssh=False):
    with open(os.path.join(ROOT, "src", "atlas", "agent.py"), "r") as stream:
        agent = stream.read()
    hosts = []
    for host in inventory["hosts"]:
        checks = host["checks"]
        if host["transport"] == "local":
            sample = capture(checks)
        elif not allow_ssh:
            sample = {"observed_at": time.time(), "checks": [missing(c, "SSH disabled") for c in checks]}
        else:
            payload = json.dumps(checks, separators=(",", ":"))
            remote = "python3 -c {} {}".format(shlex.quote(agent), shlex.quote(payload))
            command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                       "-o", "ConnectTimeout=5", "-o", "NumberOfPasswordPrompts=0", "-p",
                       str(host.get("port", 22)), "--", "{}@{}".format(host["user"], host["address"]), remote]
            try:
                response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          universal_newlines=True, timeout=20, check=True)
                sample = json.loads(response.stdout)
                items = {item["id"]: item for item in sample["checks"]}
                if len(items) != len(checks) or set(items) != set(c["id"] for c in checks):
                    raise ValueError("unexpected remote checks")
                sample["checks"] = [items[c["id"]] for c in checks]
            except (OSError, ValueError, KeyError, subprocess.SubprocessError):
                sample = {"observed_at": time.time(), "checks": [missing(c, "remote collection failed") for c in checks]}
        hosts.append({"id": host["id"], "role": host.get("role", "generic"), "transport": host["transport"],
                      "observed_at": sample["observed_at"], "checks": sample["checks"]})
    return {"schema_version": 1, "environment": inventory["environment"],
            "captured_at": time.time(), "hosts": hosts, "dependencies": inventory.get("dependencies", [])}

def evaluate(snapshot):
    hosts, states = [], {}
    for host in snapshot["hosts"]:
        checks = []
        for original in host["checks"]:
            item = dict(original)
            if item["status"] == "ok" and item.get("expected") is not None and str(item.get("observed")) != item["expected"]:
                item["status"] = "drift"
            states[(host["id"], item["id"])] = item["status"]
            checks.append(item)
        required = [c["status"] for c in checks if c.get("required", True)]
        status = "blocked" if "fail" in required or "drift" in required else "unknown" if "unknown" in required else "ready"
        hosts.append({"id": host["id"], "role": host["role"], "status": status, "checks": checks})
    mapping = {h["id"]: h for h in hosts}
    for dep in snapshot.get("dependencies", []):
        target = states[(dep["target_host"], dep["target_check"])]
        current = mapping[dep["source_host"]]
        if target in ("fail", "drift"):
            current["status"] = "blocked"
        elif target == "unknown" and current["status"] == "ready":
            current["status"] = "unknown"
    overall = "blocked" if any(h["status"] == "blocked" for h in hosts) else "unknown" if any(h["status"] == "unknown" for h in hosts) else "ready"
    return {"environment": snapshot["environment"], "status": overall, "hosts": hosts}

def render_html(report):
    esc = lambda value: html.escape(str(value if value is not None else "—"), quote=True)
    sections = ["<!doctype html><html lang='en'><meta charset='utf-8'><title>ATLAS offline report</title>",
        "<style>body{font:15px system-ui;background:#101828;color:#e7eef9;margin:30px auto;max-width:1100px;padding:0 20px}table{width:100%;border-collapse:collapse;margin-bottom:24px}td,th{text-align:left;padding:10px;border-bottom:1px solid #38465d}th{color:#adbdda}.ready,.ok{color:#92e7ac}.blocked,.fail,.drift{color:#ffb3ad}.unknown{color:#ffe29b}</style>",
        "<h1>ATLAS — Infrastructure Assurance</h1><p>Environment: {}</p><h2>Status: {}</h2>".format(esc(report["environment"]), esc(report["status"]))]
    for host in report["hosts"]:
        sections.append("<h3>{} · {}</h3><table><tr><th>Check</th><th>Kind</th><th>Status</th><th>Observed</th><th>Expected</th><th>Evidence</th></tr>".format(esc(host["id"]), esc(host["status"])))
        for check in host["checks"]:
            sections.append("<tr>" + "".join("<td>{}</td>".format(esc(check.get(key))) for key in ("id", "kind", "status", "observed", "expected", "detail")) + "</tr>")
        sections.append("</table>")
    sections.append("<p>Read-only observations. Root cause not established. Report may contain confidential infrastructure metadata.</p></html>")
    return "\n".join(sections)


def changes(before, after):
    if before is None:
        return []
    prior = {(h["id"], c["id"]): c for h in before["hosts"] for c in h["checks"]}
    current = {(h["id"], c["id"]): c for h in after["hosts"] for c in h["checks"]}
    result = []
    for host, check in sorted(set(prior) | set(current)):
        previous, latest = prior.get((host, check)), current.get((host, check))
        if previous is None or latest is None or any(previous.get(k) != latest.get(k) for k in ("status", "observed", "detail")):
            result.append({"host": host, "check": check, "before": previous.get("observed") if previous else None,
                           "after": latest.get("observed") if latest else None})
    return result

def render_comparison(changeset):
    escape = lambda value: html.escape(str(value if value is not None else "—"), quote=True)
    parts = ["<h2>Changes since previous capture</h2><table><tr><th>Host</th><th>Check</th><th>Before</th><th>After</th></tr>"]
    for item in changeset:
        parts.append("<tr>" + "".join("<td>{}</td>".format(escape(item.get(k))) for k in ("host", "check", "before", "after")) + "</tr>")
    return "\n".join(parts) + "</table>"

def main(argv=None):
    parser = argparse.ArgumentParser(description="ATLAS portable offline read-only report")
    parser.add_argument("manifest", nargs="?")
    parser.add_argument("--manifest", dest="manifest_option")
    parser.add_argument("--output", help="Legacy explicit snapshot JSON path")
    parser.add_argument("--html", help="Legacy explicit HTML report path")
    parser.add_argument("--output-dir", help="Directory for versioned reports and comparisons")
    parser.add_argument("--allow-ssh", action="store_true")
    args = parser.parse_args(argv)
    selected = args.manifest_option or args.manifest
    if not selected:
        parser.error("a manifest is required")
    try:
        with open(selected, "r") as stream:
            inventory = validate(json.load(stream))
        os.umask(0o077)
        previous = None
        previous_path = None
        if args.output_dir:
            if not os.path.isdir(args.output_dir):
                os.makedirs(args.output_dir, mode=0o700)
            previous_path = os.path.join(args.output_dir, "latest.json")
            if os.path.isfile(previous_path):
                with open(previous_path, "r") as stream:
                    previous = json.load(stream)
                if previous.get("environment") != inventory["environment"]:
                    raise ValueError("output directory belongs to another environment")
        snapshot = observe(inventory, args.allow_ssh)
        report = evaluate(snapshot)
        changed = changes(previous, snapshot)
        suffix = time.strftime("%Y%m%d-%H%M%S") + "-" + str(os.getpid())
        output = args.output or (os.path.join(args.output_dir, "capture-" + suffix + ".json") if args.output_dir else None)
        html_path = args.html or (os.path.join(args.output_dir, "capture-" + suffix + ".html") if args.output_dir else None)
        if not output:
            parser.error("--output or --output-dir is required")
        with open(output, "x") as stream:
            json.dump(snapshot, stream, indent=2, sort_keys=True)
        if html_path:
            original_html = render_html(report)
            if args.output_dir:
                original_html = original_html.replace("</html>", render_comparison(changed) + "</html>")
            with open(html_path, "x") as stream:
                stream.write(original_html)
        if previous_path:
            tmp = previous_path + ".tmp-" + str(os.getpid())
            with open(tmp, "x") as stream:
                json.dump(snapshot, stream, indent=2, sort_keys=True)
            os.replace(tmp, previous_path)
        print("ATLAS {}: {} hosts, {}, {} changes".format(report["environment"], len(report["hosts"]), report["status"], len(changed)))
        if html_path:
            print("Report:", html_path)
        return 0 if report["status"] == "ready" else 2
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("ATLAS:", exc, file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
