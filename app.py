"""Small, dependency-free web UI and API for an authorized passive web scan."""

from __future__ import annotations

import json
import mimetypes
from pathlib import Path
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scanner import ScanError, scan_url


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"


class Handler(BaseHTTPRequestHandler):
    server_version = "SafeSurfaceScanner/1.0"

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, payload: dict, status: int = 200) -> None:
        self._send_bytes(
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
        )

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/healthz":
            self._send_json({"ok": True})
            return

        path = urlparse(self.path).path
        if path == "/":
            path = "/index.html"
        if not path.startswith("/") or ".." in path:
            self._send_json({"error": "Not found"}, 404)
            return

        file_path = STATIC_DIR / path.lstrip("/")
        if not file_path.is_file() or STATIC_DIR not in file_path.parents:
            self._send_json({"error": "Not found"}, 404)
            return
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        self._send_bytes(file_path.read_bytes(), content_type)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/api/scan":
            self._send_json({"error": "Not found"}, 404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 16_384:
                raise ValueError("Corpo da requisição inválido ou grande demais")
            payload = json.loads(self.rfile.read(content_length))
            target = payload.get("url") if isinstance(payload, dict) else None
            if not isinstance(target, str):
                raise ValueError("Informe uma URL válida")
            result = scan_url(target)
            self._send_json(result)
        except (ScanError, ValueError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, 400)
        except Exception:
            self._send_json({"error": "Falha inesperada durante o scan"}, 500)

    def log_message(self, fmt: str, *args: object) -> None:
        # Keep the local tool quiet while retaining useful errors in normal logs.
        if self.command != "GET" or self.path == "/healthz":
            super().log_message(fmt, *args)


def main() -> None:
    host = "127.0.0.1"
    port = 8787
    print(f"Safe Surface Scanner: http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
