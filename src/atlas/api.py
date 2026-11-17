"""Private dashboard API, with bearer auth for all data routes."""
import hmac
import json
import os
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from .store import Store, validate_snapshot

class SnapshotInput(BaseModel):
    snapshot: dict

class EventsInput(BaseModel):
    events: list[dict]

def create_app(database=None, token=None):
    secret = token if token is not None else os.environ.get("ATLAS_API_TOKEN", "")
    if len(secret) < 24:
        raise ValueError("ATLAS_API_TOKEN must be 24+ characters")
    store = Store(database or os.environ.get("ATLAS_DB", "./atlas.sqlite3"))
    app = FastAPI(title="ATLAS", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)

    def authenticated(request: Request):
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer ") or not hmac.compare_digest(header[7:], secret):
            raise HTTPException(401, "unauthorized", headers={"WWW-Authenticate": "Bearer"})

    @app.middleware("http")
    async def headers(request: Request, call_next):
        response = await call_next(request)
        for key, value in {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                           "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
                           "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"}.items():
            response.headers[key] = value
        return response

    @app.get("/")
    def home():
        return FileResponse(Path(__file__).with_name("static") / "index.html")

    @app.get("/assets/app.js")
    def app_js():
        return FileResponse(Path(__file__).with_name("static") / "app.js", media_type="text/javascript")

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/api/environments", dependencies=[Depends(authenticated)])
    def environments():
        return store.environments()

    @app.get("/api/environments/{environment}/snapshots", dependencies=[Depends(authenticated)])
    def snapshots(environment: str):
        return store.list_snapshots(environment)

    @app.get("/api/environments/{environment}/latest", dependencies=[Depends(authenticated)])
    def latest(environment: str):
        result = store.latest(environment)
        if result is None:
            raise HTTPException(404, "environment not found")
        return result

    @app.post("/api/environments/{environment}/advice", dependencies=[Depends(authenticated)])
    def advice(environment: str):
        state = store.latest(environment)
        if state is None:
            raise HTTPException(404, "environment not found")
        if state["report"].get("stale"):
            raise HTTPException(409, "latest snapshot is stale")
        if not os.environ.get("ATLAS_OLLAMA_MODEL"):
            raise HTTPException(503, "local model not configured")
        from .intelligence import generate_advice
        try:
            return generate_advice(state["incidents"])
        except (OSError, ValueError, TimeoutError) as exc:
            raise HTTPException(503, "local model unavailable: " + type(exc).__name__) from exc

    @app.get("/api/environments/{environment}/events", dependencies=[Depends(authenticated)])
    def events(environment: str):
        return store.events(environment)

    @app.post("/api/events", status_code=201, dependencies=[Depends(authenticated)])
    def add_events(payload: EventsInput):
        try:
            return {"inserted": store.add_events(payload.events)}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/api/snapshots", status_code=201, dependencies=[Depends(authenticated)])
    def ingest(data: SnapshotInput):
        try:
            validate_snapshot(data.snapshot)
            if len(json.dumps(data.snapshot)) > 2_000_000:
                raise ValueError("snapshot too large")
            snapshot_id = store.add(data.snapshot)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {"id": snapshot_id}
    return app
