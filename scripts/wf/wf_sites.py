#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
wf_sites.py -- closed-world synthetic "websites" for split-defense experiments.

Each site i has a fixed profile derived from --seed and i (main document size,
a list of sub-resource sizes). Every visit perturbs it the way real page
loads vary: each sub-resource is kept with p=0.9, sizes jitter by +-10%,
0-3 "dynamic" extra objects are added, and the fetch order is shuffled.
Fetching uses pageload.py's server (8-byte size request, then that many bytes).

  python3 wf_sites.py --server 10.0.5.1 --sites 30 --visits 12 --log visits.csv

visits.csv: site,visit,t_start,t_end (wall clock, same clock as tcpdump).
Visits are interleaved in random order so time drift does not align with
site labels. A gap of --gap seconds separates visits.
"""
import argparse
import concurrent.futures
import math
import random
import socket
import struct
import sys
import time


def site_profile(seed, i):
    r = random.Random(seed * 1000003 + i)
    main = int(min(300e3, max(5e3, r.lognormvariate(math.log(40e3), 0.8))))
    n = r.randint(4, 40)
    objs = [int(min(1.5e6, max(500, r.lognormvariate(math.log(20e3), 1.3)))) for _ in range(n)]
    return main, objs


def visit_spec(profile, r):
    main, objs = profile
    kept = [int(o * r.uniform(0.9, 1.1)) for o in objs if r.random() < 0.9]
    kept += [int(max(500, r.lognormvariate(math.log(15e3), 1.0))) for _ in range(r.randint(0, 3))]
    r.shuffle(kept)
    return int(main * r.uniform(0.95, 1.05)), kept


def fetch(server, port, size, timeout=8):
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
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--sites", type=int, default=30)
    ap.add_argument("--visits", type=int, default=12)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--gap", type=float, default=1.2)
    ap.add_argument("--parallel", type=int, default=6)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()

    order = [(s, v) for s in range(a.sites) for v in range(a.visits)]
    rr = random.Random(a.seed + 99)
    rr.shuffle(order)
    with open(a.log, "w") as out, \
         concurrent.futures.ThreadPoolExecutor(max_workers=a.parallel) as ex:
        out.write("site,visit,t_start,t_end,bytes\n")
        for k, (site, v) in enumerate(order):
            r = random.Random(a.seed * 7919 + site * 104729 + v)
            main_sz, objs = visit_spec(site_profile(a.seed, site), r)
            t0 = time.time()
            try:
                got = fetch(a.server, a.port, main_sz)
                got += sum(ex.map(lambda sz: fetch(a.server, a.port, sz), objs))
            except OSError as e:
                print(f"visit {site}/{v} failed: {e}", file=sys.stderr)
                got = -1
            t1 = time.time()
            out.write(f"{site},{v},{t0:.6f},{t1:.6f},{got}\n")
            out.flush()
            if k % 50 == 0:
                print(f"{k}/{len(order)}", file=sys.stderr, flush=True)
            time.sleep(a.gap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
