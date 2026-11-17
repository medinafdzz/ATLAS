from fastapi.testclient import TestClient
from atlas.api import create_app
from atlas.collector import collect
from atlas.models import Manifest

TOKEN = "t" * 32

def test_protected_api(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite3"), TOKEN)
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/api/environments").status_code == 401
    headers = {"Authorization": "Bearer " + TOKEN}
    assert client.get("/api/environments", headers=headers).json() == []
    inventory = Manifest.model_validate({"schema_version":1,"environment":"test","hosts":[{"id":"local","transport":"local","checks":[{"id":"present","kind":"executable","name":"python3"}]}]})
    snapshot = collect(inventory)
    assert client.post("/api/snapshots", json={"snapshot":snapshot}, headers=headers).status_code == 201
    assert client.get("/api/environments/test/latest", headers=headers).json()["report"]["status"] == "ready"
    assert client.get("/api/environments/missing/latest", headers=headers).status_code == 404

def test_reject_invalid_import(tmp_path):
    client = TestClient(create_app(str(tmp_path / "db.sqlite3"), TOKEN))
    headers = {"Authorization": "Bearer " + TOKEN}
    assert client.post("/api/snapshots", json={"snapshot":{"schema_version":999}}, headers=headers).status_code == 422
