"""Live dashboard server (stdlib only). Runs the control loop in a background thread."""
from __future__ import annotations

import json
import mimetypes
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import PRESETS, Engine
from .llm import answer_question

DASHBOARD = Path(__file__).resolve().parents[2] / "dashboard"
RESULTS = Path(__file__).resolve().parents[2] / "results"


def load_results() -> dict:
    out = {}
    for name in ("metrics", "results", "kernel_test", "kernel_replay", "llm_eval", "llm_eval_prompt_v1",
                 "llm_eval_heldout", "replay", "replay_cic", "heldout_replay", "heldout_replay_cic"):
        f = RESULTS / f"{name}.json"
        out[name] = json.loads(f.read_text(encoding="utf-8")) if f.is_file() else None
    return out


def make_handler(engine: Engine):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the console readable
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, default=str).encode())

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/api/state":
                return self._json(engine.snapshot())
            if path == "/api/results":
                return self._json(load_results())
            if path == "/api/presets":
                return self._json(list(PRESETS))
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            target = (DASHBOARD / rel).resolve()
            if DASHBOARD in target.parents and target.is_file():
                ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
                return self._send(200, target.read_bytes(), ctype)
            self._send(404, b"not found", "text/plain")

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/api/launch":
                preset = body.get("preset")
                if preset not in PRESETS:
                    return self._json({"error": "unknown preset"}, 400)
                engine.launch(preset, duration=body.get("duration", 45))
                return self._json({"ok": True})
            if self.path == "/api/stop":
                engine.stop_attacks()
                return self._json({"ok": True})
            if self.path == "/api/report":
                from .llm_report import incident_report
                return self._json(incident_report(engine))
            if self.path == "/api/chat":
                q = (body.get("question") or "").strip()[:500]
                return self._json({"answer": answer_question(q, engine.store) if q else ""})
            self._json({"error": "not found"}, 404)

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8000, speed: float = 1.0, warmup: int = 40,
          store_path: str = "shieldwall_events.db") -> None:
    Path(store_path).unlink(missing_ok=True)  # each run starts its own timeline (t restarts at 0)
    engine = Engine(store_path=store_path)
    for _ in range(warmup):  # learn the baseline before the audience arrives
        engine.step()

    def loop():
        while True:
            start = time.time()
            engine.step()
            time.sleep(max(0.0, 1.0 / speed - (time.time() - start)))

    threading.Thread(target=loop, daemon=True).start()
    httpd = ThreadingHTTPServer((host, port), make_handler(engine))
    print(f"ShieldWall dashboard on http://{host}:{port}  (simulated lab, {speed}x speed)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
