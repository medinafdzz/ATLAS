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

def test_portable_repeated_offline_capture(tmp_path):
    output = tmp_path / "captures"
    for _ in range(2):
        result = subprocess.run([sys.executable, str(ROOT/"portable"/"atlas_portable.py"),
            "--manifest", str(ROOT/"examples"/"safe-local.json"), "--output-dir", str(output)],
            capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert len(list(output.glob("capture-*.html"))) == 2
    assert len(list(output.glob("capture-*.json"))) == 2
    assert json.loads((output/"latest.json").read_text())["environment"] == "local-lab"

def test_portable_python36_compatible_syntax():
    import ast
    for path in (ROOT/"portable"/"atlas_portable.py", ROOT/"src"/"atlas"/"agent.py"):
        ast.parse(path.read_text(), feature_version=(3, 6))
