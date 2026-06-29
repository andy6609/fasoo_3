from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

HOST = "127.0.0.1"
PORT = 9443
CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send_plain(self, status_code: int, body_text: str):
        body = body_text.encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self):
        print(f"[TLS SERVER] GET path={self.path}")

        if self.path == "/secret":
            self._send_plain(200, "tls server response contains secret data")
            return

        if self.path == "/safe":
            self._send_plain(200, "tls server safe response")
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

        print(f"[TLS SERVER] POST path={self.path}")
        print(f"[TLS SERVER] Content-Length={content_length}")
        print(f"[TLS SERVER] Body={body_text}")

        if self.path == "/upload":
            self._send_plain(200, "upload accepted by tls test server")
            return

        self._send_plain(200, "post accepted by tls test server")

    def log_message(self, format, *args):
        # 기본 http.server access log를 줄이고, 위의 직접 로그만 본다.
        return

httpd = HTTPServer((HOST, PORT), Handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"TLS test server listening on https://{HOST}:{PORT}")
print("Routes:")
print("  GET  /secret  -> response contains secret")
print("  GET  /safe    -> safe response")
print("  POST /upload  -> prints request body and returns safe response")
print("Press Ctrl+C to stop.")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nTLS test server stopped.")
