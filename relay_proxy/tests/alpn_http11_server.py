"""Minimal TLS server that advertises only HTTP/1.1 for proxy ALPN tests."""

from __future__ import annotations

import argparse
import socket
import ssl
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(["http/1.1"])

    deadline = time.monotonic() + args.timeout
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen(8)
        listener.settimeout(0.5)
        print(f"READY {args.host}:{args.port} ALPN=http/1.1", flush=True)

        while time.monotonic() < deadline:
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue

            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    print(f"NEGOTIATED {tls.selected_alpn_protocol()}", flush=True)
                    tls.settimeout(3.0)
                    request = bytearray()
                    while b"\r\n\r\n" not in request and len(request) < 65536:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        request.extend(chunk)

                    body = b"HTTP/1.1 ALPN TEST OK\n"
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode("ascii")
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
                    tls.sendall(response)
            except (OSError, ssl.SSLError) as exc:
                print(f"CONNECTION_ERROR {exc}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
