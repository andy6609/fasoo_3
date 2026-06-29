from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import gzip
import zlib
from urllib.parse import parse_qs

HOST = "127.0.0.1"
PORT = 9443
CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"


def html_page() -> str:
    # Important: Do not include sensitive sample strings in this HTML page.
    # The DLP response scanner would correctly block this page if it contained them.
    return """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>Local DLP Browser MITM Test</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 920px; margin: 40px auto; line-height: 1.55; }
    code { background: #f3f3f3; padding: 2px 5px; border-radius: 4px; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 18px; margin: 16px 0; }
    input { width: 420px; max-width: 90%; padding: 8px; }
    button { padding: 8px 14px; cursor: pointer; }
  </style>
</head>
<body>
  <h1>Local DLP Browser MITM Test</h1>
  <p>이 페이지가 인증서 경고 없이 열리면 Root CA 신뢰 등록과 SNI 동적 인증서 발급이 성공한 것입니다.</p>

  <div class="card">
    <h2>1. Safe response</h2>
    <p><a href="/safe">/safe 열기</a></p>
  </div>

  <div class="card">
    <h2>2. Blocked response test</h2>
    <p>아래 링크는 서버 응답 본문에 차단 키워드를 포함합니다.</p>
    <p><a href="/blocked-response">차단 응답 테스트 열기</a></p>
  </div>

  <div class="card">
    <h2>3. Request body DLP test</h2>
    <p>아래 입력칸에 테스트 문장을 직접 입력하고 제출하면 요청 본문 검사를 확인할 수 있습니다.</p>
    <form method="POST" action="/upload">
      <input name="message" placeholder="여기에 테스트 문자열 입력">
      <button type="submit">POST /upload</button>
    </form>
  </div>

  <div class="card">
    <h2>4. Multipart file upload DLP test</h2>
    <p>로컬 테스트 파일을 선택해 업로드하면 multipart/form-data 파일 업로드 검사를 확인할 수 있습니다.</p>
    <form method="POST" action="/file-upload" enctype="multipart/form-data">
      <p><input type="file" name="document"></p>
      <p><input name="note" placeholder="업로드 메모"></p>
      <button type="submit">POST /file-upload</button>
    </form>
    <p>대용량 테스트는 CMD에서 <code>curl -F "document=@multipart_test_files\large_safe_5mb.txt"</code> 형태로 실행합니다.</p>
  </div>

  <div class="card">
    <h2>5. Compressed response DLP test</h2>
    <p>아래 링크는 gzip/deflate로 압축된 HTTPS 응답 본문을 검사하는 테스트입니다.</p>
    <p><a href="/gzip-safe">/gzip-safe 열기</a></p>
    <p><a href="/gzip-secret">/gzip-secret 차단 테스트</a></p>
    <p><a href="/deflate-safe">/deflate-safe 열기</a></p>
    <p><a href="/deflate-secret">/deflate-secret 차단 테스트</a></p>
  </div>

  <div class="card">
    <h2>6. Chunked response DLP test</h2>
    <p>아래 링크는 Content-Length 없이 Transfer-Encoding: chunked 응답을 검사하는 테스트입니다.</p>
    <p><a href="/chunked-safe">/chunked-safe 열기</a></p>
    <p><a href="/chunked-secret">/chunked-secret 차단 테스트</a></p>
    <p><a href="/chunked-gzip-safe">/chunked-gzip-safe 열기</a></p>
    <p><a href="/chunked-gzip-secret">/chunked-gzip-secret 차단 테스트</a></p>
  </div>

  <p>브라우저 주소: <code>https://demo.local:9443/</code></p>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _client_wants_close(self) -> bool:
        value = self.headers.get("Connection", "")
        return value.lower() == "close"

    def _send_bytes(self, status_code: int, body: bytes, content_type: str, force_close: bool = False):
        should_close = force_close or self._client_wants_close()

        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close" if should_close else "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

        self.close_connection = should_close

    def _send_text(self, status_code: int, body_text: str, force_close: bool = False):
        self._send_bytes(status_code, body_text.encode("utf-8"), "text/plain; charset=utf-8", force_close)

    def _send_html(self, status_code: int, html_text: str, force_close: bool = False):
        self._send_bytes(status_code, html_text.encode("utf-8"), "text/html; charset=utf-8", force_close)

    def _send_compressed_text(self, status_code: int, body_text: str, encoding: str, force_close: bool = False):
        plain_body = body_text.encode("utf-8")

        if encoding == "gzip":
            compressed_body = gzip.compress(plain_body)
        elif encoding == "deflate":
            compressed_body = zlib.compress(plain_body)
        else:
            raise ValueError(f"unsupported encoding: {encoding}")

        should_close = force_close or self._client_wants_close()
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(compressed_body)))
        self.send_header("Connection", "close" if should_close else "keep-alive")
        self.end_headers()
        self.wfile.write(compressed_body)
        self.wfile.flush()
        self.close_connection = should_close

    def _write_chunked_body(self, body: bytes, chunk_sizes=None):
        if chunk_sizes is None:
            chunk_sizes = [7, 11, 5, 8192]

        offset = 0
        index = 0
        while offset < len(body):
            size = chunk_sizes[index % len(chunk_sizes)]
            chunk = body[offset:offset + size]
            offset += len(chunk)
            index += 1
            self.wfile.write((f"{len(chunk):X}\r\n").encode("ascii"))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")

        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _send_chunked_text(self, status_code: int, body_text: str, force_close: bool = False):
        body = body_text.encode("utf-8")
        should_close = force_close or self._client_wants_close()
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close" if should_close else "keep-alive")
        self.end_headers()
        self._write_chunked_body(body)
        self.close_connection = should_close

    def _send_chunked_compressed_text(self, status_code: int, body_text: str, encoding: str, force_close: bool = False):
        plain_body = body_text.encode("utf-8")
        if encoding == "gzip":
            body = gzip.compress(plain_body)
        elif encoding == "deflate":
            body = zlib.compress(plain_body)
        else:
            raise ValueError(f"unsupported encoding: {encoding}")

        should_close = force_close or self._client_wants_close()
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Encoding", encoding)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close" if should_close else "keep-alive")
        self.end_headers()
        self._write_chunked_body(body)
        self.close_connection = should_close

    def _read_chunked_body(self) -> bytes:
        body = bytearray()
        while True:
            size_line = self.rfile.readline()
            if not size_line:
                break
            size_text = size_line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                break
            if size == 0:
                # consume trailers until empty line
                while True:
                    trailer = self.rfile.readline()
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                break
            body.extend(self.rfile.read(size))
            self.rfile.read(2)  # CRLF after chunk data
        return bytes(body)

    def _read_request_body(self) -> bytes:
        transfer_encoding = self.headers.get("Transfer-Encoding", "")
        if "chunked" in transfer_encoding.lower():
            return self._read_chunked_body()

        content_length_text = self.headers.get("Content-Length", "0")
        try:
            content_length = int(content_length_text)
        except ValueError:
            content_length = 0
        return self.rfile.read(content_length) if content_length > 0 else b""

    def do_GET(self):
        print(f"[TLS BROWSER SERVER] GET path={self.path} host={self.headers.get('Host', '-')} connection={self.headers.get('Connection', '-')}")

        if self.path == "/" or self.path == "/index.html":
            self._send_html(200, html_page())
            return

        if self.path == "/safe":
            self._send_text(200, "browser safe response from local TLS server")
            return

        if self.path == "/blocked-response":
            self._send_text(200, "browser response contains secret data and should be blocked")
            return

        if self.path == "/gzip-safe":
            self._send_compressed_text(200, "gzip safe response from local TLS server", "gzip")
            return

        if self.path == "/gzip-secret":
            self._send_compressed_text(200, "gzip response contains secret data and should be blocked", "gzip")
            return

        if self.path == "/deflate-safe":
            self._send_compressed_text(200, "deflate safe response from local TLS server", "deflate")
            return

        if self.path == "/deflate-secret":
            self._send_compressed_text(200, "deflate response contains secret data and should be blocked", "deflate")
            return

        if self.path == "/chunked-safe":
            self._send_chunked_text(200, "chunked safe response from local TLS server")
            return

        if self.path == "/chunked-secret":
            self._send_chunked_text(200, "chunked response contains secret data and should be blocked")
            return

        if self.path == "/chunked-gzip-safe":
            self._send_chunked_compressed_text(200, "chunked gzip safe response from local TLS server", "gzip")
            return

        if self.path == "/chunked-gzip-secret":
            self._send_chunked_compressed_text(200, "chunked gzip response contains secret data and should be blocked", "gzip")
            return

        if self.path == "/favicon.ico":
            self._send_bytes(404, b"", "text/plain", force_close=True)
            return

        self._send_text(404, "not found", force_close=True)

    def do_POST(self):
        body = self._read_request_body()
        body_text = body.decode("utf-8", errors="replace")

        print(f"[TLS BROWSER SERVER] POST path={self.path} host={self.headers.get('Host', '-')} connection={self.headers.get('Connection', '-')}")
        print(f"[TLS BROWSER SERVER] Content-Type={self.headers.get('Content-Type', '-')}")
        print(f"[TLS BROWSER SERVER] Transfer-Encoding={self.headers.get('Transfer-Encoding', '-')}")
        print(f"[TLS BROWSER SERVER] Content-Length={self.headers.get('Content-Length', '-')}")
        print(f"[TLS BROWSER SERVER] Body bytes={len(body)}")
        if len(body) <= 4096:
            print(f"[TLS BROWSER SERVER] Body={body_text}")
        else:
            preview = body[:512].decode("utf-8", errors="replace")
            print(f"[TLS BROWSER SERVER] Body preview first 512 bytes={preview!r}")

        parsed = parse_qs(body_text if len(body) <= 1048576 else "")
        message = parsed.get("message", [body_text[:512]])[0]

        if self.path == "/upload":
            self._send_html(
                200,
                "<!doctype html><meta charset='utf-8'><h1>Upload accepted</h1>"
                "<p>The upstream TLS browser test server received the POST request.</p>"
                "<p>If you expected a DLP block, check whether the request contained a policy-matching pattern.</p>"
                "<p><a href='/'>Back</a></p>"
            )
            print(f"[TLS BROWSER SERVER] Parsed message={message}")
            return

        if self.path == "/chunked-upload":
            self._send_html(
                200,
                "<!doctype html><meta charset='utf-8'><h1>Chunked upload accepted</h1>"
                "<p>The upstream TLS browser test server received the chunked POST request.</p>"
                "<p>If a DLP rule matched, this page should not appear.</p>"
                "<p><a href='/'>Back</a></p>"
            )
            print(f"[TLS BROWSER SERVER] Parsed chunked message={message}")
            return

        if self.path == "/file-upload":
            self._send_html(
                200,
                "<!doctype html><meta charset='utf-8'><h1>File upload accepted</h1>"
                "<p>The upstream TLS browser test server received the multipart request.</p>"
                "<p>If a DLP rule matched, this page should not appear.</p>"
                "<p><a href='/'>Back</a></p>"
            )
            return

        self._send_text(404, "not found", force_close=True)

    def log_message(self, format, *args):
        return


httpd = HTTPServer((HOST, PORT), Handler)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"TLS browser test server listening on https://{HOST}:{PORT}")
print("Browser URL through proxy:")
print("  https://demo.local:9443/")
print("Routes:")
print("  GET  /                  -> HTML test page")
print("  GET  /safe              -> safe response")
print("  GET  /blocked-response  -> response body contains blocked keyword")
print("  GET  /gzip-safe         -> gzip compressed safe response")
print("  GET  /gzip-secret       -> gzip compressed response body contains blocked keyword")
print("  GET  /deflate-safe      -> deflate compressed safe response")
print("  GET  /deflate-secret    -> deflate compressed response body contains blocked keyword")
print("  GET  /chunked-safe      -> chunked safe response")
print("  GET  /chunked-secret    -> chunked response body contains blocked keyword")
print("  GET  /chunked-gzip-safe -> chunked + gzip safe response")
print("  GET  /chunked-gzip-secret -> chunked + gzip body contains blocked keyword")
print("  POST /upload            -> prints browser request body")
print("  POST /chunked-upload    -> reads chunked request body")
print("  POST /file-upload       -> multipart browser file upload test, including large upload size tests")
print("Press Ctrl+C to stop.")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nTLS browser test server stopped.")
