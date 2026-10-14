#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
pageload.py -- synthetic "web page load" workload for multipath split tests.

A page is one main object fetched alone, then a set of sub-resources fetched
over up to --parallel concurrent TCP connections (one object per connection,
HTTP/1.1-style). The request is tiny (8 bytes), the response is the object,
so the bulk of the bytes flows server -> client like a real page load.

  server: python3 pageload.py server --bind 10.0.0.1 --port 8080
  client: python3 pageload.py client --server 10.0.0.1 --port 8080 \
              --spec "60000|180000,25000,600000,9000" --parallel 6

--spec: "<main>|<obj>,<obj>,..."  sizes in bytes. A bare number is a single
object (bulk transfer).
"""
import argparse
import concurrent.futures
import json
import os
import socket
import socketserver
import struct
import sys
import time

CHUNK = os.urandom(64 * 1024)  # incompressible payload


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        hdr = b""
        while len(hdr) < 8:
            part = self.request.recv(8 - len(hdr))
            if not part:
                return
            hdr += part
        (size,) = struct.unpack("!Q", hdr)
        left = size
        while left > 0:
            n = min(left, len(CHUNK))
            self.request.sendall(CHUNK[:n])
            left -= n
        try:
            self.request.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def fetch(server, port, size, timeout):
    t0 = time.monotonic()
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.sendall(struct.pack("!Q", size))
        got = 0
        # Stop at the announced size instead of waiting for the server's FIN:
        # the hybrid lane occasionally delays FIN propagation, which would
        # otherwise stall the visit until the socket timeout.
        while got < size:
            b = s.recv(min(256 * 1024, size - got))
            if not b:
                break
            got += len(b)
    if got != size:
        raise RuntimeError(f"short read {got}/{size}")
    return got, time.monotonic() - t0


def parse_spec(spec):
    if "|" in spec:
        main, rest = spec.split("|", 1)
        objs = [int(x) for x in rest.split(",") if x.strip()]
        return int(main), objs
    return int(spec), []


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server")
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    c = sub.add_parser("client")
    c.add_argument("--server", required=True)
    c.add_argument("--port", type=int, default=8080)
    c.add_argument("--spec", required=True)
    c.add_argument("--parallel", type=int, default=6)
    c.add_argument("--timeout", type=float, default=60.0)
    a = ap.parse_args()

    if a.mode == "server":
        with Server((a.bind, a.port), Handler) as srv:
            srv.serve_forever()
        return

    main_obj, objs = parse_spec(a.spec)
    t0 = time.monotonic()
    total, _ = fetch(a.server, a.port, main_obj, a.timeout)
    if objs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.parallel) as ex:
            for got, _ in ex.map(lambda sz: fetch(a.server, a.port, sz, a.timeout), objs):
                total += got
    dt = time.monotonic() - t0
    print(json.dumps({"bytes": total, "seconds": round(dt, 3),
                      "mbps": round(total * 8 / dt / 1e6, 2)}))


if __name__ == "__main__":
    sys.exit(main())
