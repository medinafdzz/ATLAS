"""Bounded structured event records and cautious temporal correlation."""
import re
import time

NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
KINDS = ("deployment", "configuration", "service", "incident", "build", "change")
LEVELS = ("info", "warning", "error")

def validate_event(event):
    required = {"environment", "host", "source", "kind", "level", "occurred_at", "summary"}
    if not isinstance(event, dict) or set(event) != required:
        raise ValueError("invalid event object")
    for key in ("environment", "host", "source"):
        if not isinstance(event[key], str) or not NAME.fullmatch(event[key]):
            raise ValueError("invalid event identifier")
    if event["kind"] not in KINDS or event["level"] not in LEVELS:
        raise ValueError("invalid event category")
    timestamp = event["occurred_at"]
    if not isinstance(timestamp, (float, int)) or not 0 < timestamp <= time.time() + 300:
        raise ValueError("invalid event timestamp")
    summary = event["summary"]
    if not isinstance(summary, str) or not 1 <= len(summary) <= 300 or "\x00" in summary:
        raise ValueError("invalid summary")
    return event

def correlate(incidents, events, captured_at, window_seconds=900):
    by_host = {}
    for event in events:
        if abs(captured_at - event["occurred_at"]) <= window_seconds:
            by_host.setdefault(event["host"], []).append(event)
    return [{**incident, "related_events": by_host.get(incident["host"], [])[:3],
             "relationship": "same host and time window; not proven causal"
             if by_host.get(incident["host"]) else None} for incident in incidents]
