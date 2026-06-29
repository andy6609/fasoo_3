from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

HOST = "127.0.0.1"
PORT = 9443
CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _client_wants_close(self) -> bool:
        value = self.headers.get("Connection", "")
        return value.lower() == "close"

    def _send_plain(self, status_code: int, body_text: str, force_close: bool = False):
        body = body_text.encode("utf-8")
        should_close = force_close or self._client_wants_close()

        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close" if should_close else "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

        self.close_connection = should_close

    def do_GET(self):
        print(f"[TLS SERVER] GET path={self.path} connection={self.headers.get('Connection', '-')}")

        if self.path == "/secret":
            self._send_plain(200, "tls server response contains secret data")
            return

        if self.path == "/safe":
            self._send_plain(200, "tls server safe keep-alive response")
            return

        self._send_plain(200, "tls server default safe response")

    def do_POST(self):
        content_length_text = self.headers.get("Content-Length", "0")

        try:
            content_length = int(content_length_text)
        except ValueError:
            content_length = 0

        body = self.rfile.read(content_length) if content_length > 0 else b""
        body_text = body.decode("utf-8", errors="replace")

        print(f"[TLS SERVER] POST path={self.path} connection={self.headers.get('Connection', '-')}")
        print(f"[TLS SERVER] Content-Length={content_length}")
        print(f"[TLS SERVER] Body={body_text}")

        if self.path == "/upload":
            self._send_plain(200, "upload accepted by keep-alive tls test server")
            return

        self._send_plain(200, "post accepted by keep-alive tls test server")

    def log_message(self, format, *args):
        return

httpd = HTTPServer((HOST, PORT), Handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"TLS keep-alive test server listening on https://{HOST}:{PORT}")
print("Routes:")
print("  GET  /safe    -> safe keep-alive response")
print("  GET  /secret  -> response contains secret")
print("  POST /upload  -> prints request body and returns safe response")
print("Press Ctrl+C to stop.")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nTLS keep-alive test server stopped.")
