#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
pcap_split.py -- turn per-path tunnel captures into the traces a single-path
observer would record.

  python3 pcap_split.py --client-ip 192.168.10.1,192.168.20.1 \
      --port 4433 --out trace.csv pathA.pcap pathB.pcap

Each pcap is one access path (capture on the client-side interface). Output:
  - trace.csv: t_rel, path, dir (+1 up / -1 down), wire_len   (one row per
    tunnel packet; the format most WF pipelines ingest)
  - a JSON summary on stdout: per path, packets/bytes per direction and the
    path's share of the total.
Only UDP packets to/from --port are kept (the QUIC tunnel itself).
"""
import argparse
import json
import socket
import struct
import sys


def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian = ">"
        else:
            raise ValueError(f"{path}: not a classic pcap (pcapng unsupported)")
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            sec, frac, incl, orig = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            ts = sec + frac / (1e9 if nano else 1e6)
            yield ts, orig, linktype, data


def ip_payload(linktype, data):
    if linktype == 1:            # Ethernet
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        if etype == 0x8100 and len(data) >= 18:
            etype = struct.unpack("!H", data[16:18])[0]
            off = 18
        return data[off:] if etype in (0x0800, 0x86DD) else None
    if linktype == 113:          # Linux cooked (SLL)
        return data[16:]
    if linktype in (101, 12):    # raw IP
        return data
    return None


def parse_udp(ip):
    if not ip:
        return None
    v = ip[0] >> 4
    if v == 4 and len(ip) >= 20 and ip[9] == 17:
        ihl = (ip[0] & 0x0F) * 4
        src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        if len(ip) < ihl + 4:
            return None
        sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        return src, dst, sport, dport
    if v == 6 and len(ip) >= 44 and ip[6] == 17:
        src = socket.inet_ntop(socket.AF_INET6, ip[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, ip[24:40])
        sport, dport = struct.unpack("!HH", ip[40:44])
        return src, dst, sport, dport
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-ip", required=True,
                    help="comma-separated client-side tunnel endpoint IPs")
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--out", default=None)
    ap.add_argument("pcaps", nargs="+")
    a = ap.parse_args()
    client_ips = set(a.client_ip.split(","))

    rows = []
    for idx, p in enumerate(a.pcaps):
        for ts, orig, lt, data in read_pcap(p):
            u = parse_udp(ip_payload(lt, data))
            if not u:
                continue
            src, dst, sport, dport = u
            if a.port not in (sport, dport):
                continue
            d = +1 if src in client_ips else -1
            rows.append((ts, idx, d, orig))
    if not rows:
        print(json.dumps({"error": "no tunnel packets"}))
        return 1
    rows.sort()
    t0 = rows[0][0]

    if a.out:
        with open(a.out, "w") as f:
            f.write("t_rel,path,dir,wire_len\n")
            for ts, idx, d, ln in rows:
                f.write(f"{ts - t0:.6f},{idx},{d},{ln}\n")

    tot_dn = sum(r[3] for r in rows if r[2] < 0) or 1
    tot_up = sum(r[3] for r in rows if r[2] > 0) or 1
    summary = {}
    for idx, p in enumerate(a.pcaps):
        mine = [r for r in rows if r[1] == idx]
        dn = [r for r in mine if r[2] < 0]
        up = [r for r in mine if r[2] > 0]
        summary[p] = {
            "pkts_down": len(dn), "bytes_down": sum(r[3] for r in dn),
            "pkts_up": len(up), "bytes_up": sum(r[3] for r in up),
            "share_down": round(sum(r[3] for r in dn) / tot_dn, 4),
            "share_up": round(sum(r[3] for r in up) / tot_up, 4),
        }
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
