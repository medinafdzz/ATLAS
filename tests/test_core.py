import json
import pytest
from atlas.agent import probe
from atlas.analysis import diff, diagnose, evaluate
from atlas.collector import collect
from atlas.models import Manifest
from atlas.store import Store, validate_snapshot

def inventory():
    return Manifest.model_validate({"schema_version": 1, "environment": "lab",
        "hosts": [{"id": "h", "transport": "local", "checks": [
            {"id": "python", "kind": "executable", "name": "python3"},
            {"id": "missing", "kind": "file", "name": "/nonexistent/atlas-test"}]}]})

def test_capture_readiness_and_diagnosis():
    result = evaluate(collect(inventory()))
    assert result["status"] == "blocked"
    assert result["totals"]["fail"] == 1
    assert len(diagnose(result)) == 1

def test_drift():
    original = collect(inventory())
    modified = json.loads(json.dumps(original))
    modified["hosts"][0]["checks"][0]["expected"] = "incorrect"
    assert evaluate(modified)["totals"]["drift"] == 1
    modified["hosts"][0]["checks"][0]["observed"] = "changed"
    assert diff(original, modified)["total"] == 1

def test_store(tmp_path):
    store = Store(tmp_path / "store.sqlite3")
    snapshot = collect(inventory())
    assert store.add(snapshot) == 1
    assert store.environments()[0]["snapshots"] == 1
    assert store.latest("lab")["report"]["status"] == "blocked"
    assert store.latest("notfound") is None

def test_ssh_is_opt_in():
    remote = Manifest.model_validate({"schema_version":1,"environment":"lab","hosts":[{"id":"remote","transport":"ssh","address":"example.org","user":"observer","checks":[{"id":"proc","kind":"process","name":"worker"}]}]})
    assert collect(remote)["hosts"][0]["checks"][0]["status"] == "unknown"

def test_manifest_rejects_injection():
    with pytest.raises(ValueError):
        Manifest.model_validate({"schema_version":1,"environment":"lab","hosts":[{"id":"h","transport":"ssh","address":"bad;whoami","user":"observer","checks":[{"id":"p","kind":"process","name":"nginx"}]}]})

def test_symlink_and_hash(tmp_path):
    path = tmp_path / "file"
    path.write_text("hello")
    assert probe({"kind":"file","name":str(path)})["observed"].startswith("sha256:")
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "missing")
    assert probe({"kind":"symlink","name":str(link)})["status"] == "fail"

def test_reject_invalid_snapshot():
    snapshot = collect(inventory())
    snapshot["hosts"][0]["checks"][0]["status"] = "invented"
    with pytest.raises(ValueError):
        validate_snapshot(snapshot)

def test_unknown_is_not_ready():
    snapshot = collect(inventory())
    snapshot["hosts"][0]["checks"][1]["status"] = "unknown"
    assert evaluate(snapshot)["status"] == "unknown"

def test_watch_once(tmp_path):
    from atlas.cli import main
    from pathlib import Path
    manifest = Path(__file__).parents[1] / "examples" / "lab.json"
    assert main(["watch", str(manifest), "--db", str(tmp_path / "watch.sqlite3"), "--once"]) == 0
    assert Store(tmp_path / "watch.sqlite3").environments()[0]["snapshots"] == 1

def test_declared_dependency_blocks_dependent_service():
    from atlas.store import validate_snapshot
    manifest = Manifest.model_validate({"schema_version":1,"environment":"test","hosts":[
        {"id":"web","transport":"local","checks":[{"id":"process","kind":"executable","name":"python3"}]},
        {"id":"db","transport":"local","checks":[{"id":"service","kind":"file","name":"/missing/atlas-db"}]}],
        "dependencies":[{"source_host":"web","source_check":"process","target_host":"db","target_check":"service"}]})
    snap = collect(manifest)
    validate_snapshot(snap)
    report = evaluate(snap)
    assert report["hosts"][0]["status"] == "blocked"
    assert report["hosts"][0]["blocked_by"][0]["target_host"] == "db"

def test_dependency_endpoints_are_validated():
    with pytest.raises(ValueError):
        Manifest.model_validate({"schema_version":1,"environment":"test","hosts":[
            {"id":"h","transport":"local","checks":[{"id":"c","kind":"executable","name":"sh"}]}],
            "dependencies":[{"source_host":"h","source_check":"c","target_host":"h","target_check":"absent"}]})

def test_stale_snapshots_are_not_current_health():
    original = collect(inventory())
    original["captured_at"] -= 3600
    report = evaluate(original)
    assert report["stale"] is True
    assert report["status"] == "unknown"
    assert all(host["status"] == "unknown" for host in report["hosts"])

def test_consistent_backup_does_not_overwrite(tmp_path):
    store = Store(tmp_path / "data.sqlite3")
    store.add(collect(inventory()))
    backup = tmp_path / "backup.sqlite3"
    assert store.backup(backup) == str(backup)
    assert Store(backup).environments()[0]["snapshots"] == 1
    with pytest.raises(FileExistsError):
        store.backup(backup)
