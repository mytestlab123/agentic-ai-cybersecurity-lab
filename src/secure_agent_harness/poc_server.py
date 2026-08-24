"""Small dependency-free local web server for the Issue 5 visual proof."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .contracts import PocRequest
from .poc import PocEngine


_HTML_PATH = Path(__file__).resolve().parents[2] / "web" / "poc_chat.html"
_ENGINE = PocEngine()


def _session_payload(session: Any) -> dict[str, object]:
    return {
        "result": session.result.model_dump(mode="json"),
        "events": [event.model_dump(mode="json") for event in session.events],
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = "secure-agent-poc/1.0"

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, object] | None:
        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            return None
        if length < 0 or length > 16_384:
            return None
        try:
            payload = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/api/health":
            self._send_json(200, {"status": "OK", "mode": "LOCAL_SYNTHETIC"})
            return
        if self.path != "/":
            self._send_json(404, {"status": "BLOCKED", "reason_code": "NOT_FOUND"})
            return
        try:
            body = _HTML_PATH.read_bytes()
        except OSError:
            self._send_json(500, {"status": "FAILED", "reason_code": "UI_ASSET_MISSING"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        payload = self._read_json()
        if payload is None:
            self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
            return

        if self.path == "/api/run":
            try:
                request = PocRequest.model_validate(payload)
            except ValidationError:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            session = _ENGINE.start(request)
            self._send_json(200, _session_payload(session))
            return

        if self.path == "/api/decision":
            run_id = payload.get("run_id")
            decision = payload.get("decision")
            if not isinstance(run_id, str) or decision not in {"APPROVE", "REJECT"}:
                self._send_json(400, {"status": "BLOCKED", "reason_code": "REQUEST_REJECTED"})
                return
            try:
                session = _ENGINE.decide(run_id, decision == "APPROVE")
            except KeyError:
                self._send_json(404, {"status": "BLOCKED", "reason_code": "RUN_NOT_FOUND"})
                return
            self._send_json(200, _session_payload(session))
            return

        self._send_json(404, {"status": "BLOCKED", "reason_code": "NOT_FOUND"})

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def main() -> None:
    try:
        port = int(os.environ.get("POC_PORT", "8765"))
    except ValueError as exc:
        raise SystemExit("POC_PORT must be an integer.") from exc
    if not 1024 <= port <= 65535:
        raise SystemExit("POC_PORT must be between 1024 and 65535.")
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"Issue 5 local POC: http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
