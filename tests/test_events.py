import time
import pytest
from atlas.events import correlate, validate_event
from atlas.store import Store

def record():
    return {"environment":"lab", "host":"node1", "source":"deployment", "kind":"deployment",
            "level":"warning", "occurred_at":time.time(), "summary":"New deployment observed"}

def test_event_storage_and_correlation(tmp_path):
    store = Store(tmp_path / "db.sqlite3")
    assert store.add_events([record()]) == 1
    event = store.events("lab")[0]
    related = correlate([{"host":"node1","check":"health"}], [event], time.time())
    assert related[0]["related_events"][0]["source"] == "deployment"
    assert "not proven causal" in related[0]["relationship"]

def test_invalid_event_category_rejected():
    value = record()
    value["kind"] = "unsafe"
    with pytest.raises(ValueError):
        validate_event(value)

def test_event_batch_bounded(tmp_path):
    with pytest.raises(ValueError):
        Store(tmp_path / "events.sqlite3").add_events([record()] * 101)
