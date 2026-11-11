"""Local HTTP JSON endpoint. Bind loopback only, token required for POST.

This is a demonstration endpoint, not a hardened production service.
"""
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from .core import ValidationError, assess


class Handler(BaseHTTPRequestHandler):
    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"status": "ok", "mode": "local-demo"})
        return self._json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/triage":
            return self._json(404, {"error": "not_found"})
        expected = os.environ["TRIAGE_DEMO_TOKEN"]
        supplied = self.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied, "Bearer " + expected):
            return self._json(401, {"error": "unauthorized"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8192:
                return self._json(413, {"error": "request_size_invalid"})
            payload = json.loads(self.rfile.read(length))
            result = assess(payload)
        except (ValueError, ValidationError, json.JSONDecodeError) as exc:
            return self._json(400, {"error": "invalid_event", "detail": str(exc)[:160]})
        return self._json(200, result)


def main():
    token = os.environ.get("TRIAGE_DEMO_TOKEN", "")
    if len(token) < 16:
        raise SystemExit("Set TRIAGE_DEMO_TOKEN to a unique value of at least 16 characters")
    host, port = "127.0.0.1", 8765
    print(f"Demo only: http://{host}:{port} (localhost, no TLS)")
    HTTPServer((host, port), Handler).serve_forever()

if __name__ == "__main__":
    main()
