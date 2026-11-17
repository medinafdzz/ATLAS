import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).parents[1]

def test_portable_local_report(tmp_path):
    snapshot, report = tmp_path/"snapshot.json", tmp_path/"report.html"
    completed = subprocess.run([sys.executable, str(ROOT/"portable"/"atlas_portable.py"),
        str(ROOT/"examples"/"lab.json"), "--output", str(snapshot), "--html", str(report)],
        capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(snapshot.read_text())["environment"] == "demo-lab"
    assert "ATLAS" in report.read_text()

def test_portable_rejects_bad_target(tmp_path):
    manifest = tmp_path/"bad.json"
    manifest.write_text(json.dumps({"schema_version":1,"environment":"lab","hosts":[
        {"id":"h","transport":"ssh","address":"unsafe;command","user":"user",
         "checks":[{"id":"check","kind":"executable","name":"sh"}]}]}))
    output = tmp_path/"output.json"
    completed = subprocess.run([sys.executable, str(ROOT/"portable"/"atlas_portable.py"),
        str(manifest), "--output", str(output)], capture_output=True, text=True)
    assert completed.returncode == 1
    assert not output.exists()
