"""ATLAS command-line application."""
import argparse
import json
import os
import sys
from pathlib import Path
from . import __version__
from .analysis import evaluate
from .collector import collect
from .models import Manifest
from .store import Store

def main(argv=None):
    parser = argparse.ArgumentParser(prog="atlas", description="Read-only infrastructure assurance")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("capture", help="Collect checks from explicit inventory")
    cmd.add_argument("manifest")
    cmd.add_argument("--output", required=True)
    cmd.add_argument("--allow-ssh", action="store_true")
    cmd = commands.add_parser("inspect", help="Evaluate snapshot readiness")
    cmd.add_argument("snapshot")
    cmd = commands.add_parser("import", help="Import snapshot into SQLite")
    cmd.add_argument("snapshot")
    cmd.add_argument("--db", default=os.environ.get("ATLAS_DB", "./atlas.sqlite3"))
    cmd = commands.add_parser("serve", help="Run private dashboard")
    cmd.add_argument("--host", default="127.0.0.1")
    cmd.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            manifest = Manifest.model_validate_json(Path(args.manifest).read_text(encoding="utf-8"))
            Path(args.output).write_text(json.dumps(collect(manifest, allow_ssh=args.allow_ssh), indent=2) + "\n", encoding="utf-8")
            print("snapshot saved:", args.output)
            return 0
        if args.command == "inspect":
            result = evaluate(json.loads(Path(args.snapshot).read_text(encoding="utf-8")))
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "ready" else 2
        if args.command == "import":
            print("snapshot ID:", Store(args.db).add(json.loads(Path(args.snapshot).read_text(encoding="utf-8"))))
            return 0
        if args.command == "serve":
            import uvicorn
            from .api import create_app
            uvicorn.run(create_app(), host=args.host, port=args.port, proxy_headers=False)
            return 0
    except (ValueError, OSError) as exc:
        print("ATLAS:", exc, file=sys.stderr)
        return 1
    return 1

if __name__ == "__main__":
    sys.exit(main())
