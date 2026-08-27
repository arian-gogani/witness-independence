"""
A8: an anchor that looks independent and answers from the subject's own host.

Runs a loopback server for the duration of the check. This case cannot be
expressed as a static fixture, because the whole point is what happens between
the request and the response.
"""
import base64, hashlib, json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from nacl.signing import SigningKey

PORT = 8199
SEED = b"wil-a8-redirect"
SK = SigningKey(hashlib.sha256(SEED).digest())
KID = "a8-2026"
JWKS = {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": KID, "use": "sig",
                  "x": base64.urlsafe_b64encode(SK.verify_key.encode()).decode().rstrip("=")}]}

# The subject's own authority. The witness path 302s here.
SUBJECT = f"did:web:localhost%3A{PORT}"
WITNESS_URL = f"http://127.0.0.1:{PORT}/witness/.well-known/jwks.json"
HONEST_URL = f"http://127.0.0.1:{PORT}/honest/.well-known/jwks.json"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/witness/.well-known/jwks.json":
            self.send_response(302)
            self.send_header("Location",
                             f"http://localhost:{PORT}/subject/.well-known/jwks.json")
            self.end_headers()
            return
        if self.path.endswith("/.well-known/jwks.json"):
            body = json.dumps(JWKS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


class Server:
    def __init__(self):
        self.httpd = HTTPServer(("127.0.0.1", PORT), _Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def receipt():
    """A receipt that names an independent issuer and is correctly signed."""
    def jcs(o):
        return json.dumps(o, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode()
    payload = {"type": "decision_receipt", "subject": SUBJECT, "decision": "allow",
               "action": {"kind": "Read", "target": "/tmp/x"}, "sequence": 0,
               "timestamp": "2026-08-27T00:00:00Z"}
    return {"v": 2, "type": "decision_receipt", "algorithm": "ed25519", "kid": KID,
            "issuer": "did:web:witness.test", "payload": payload,
            "signature": base64.urlsafe_b64encode(
                SK.sign(jcs(payload)).signature).decode().rstrip("=")}
