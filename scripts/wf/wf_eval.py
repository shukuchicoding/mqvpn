#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
wf_eval.py -- closed-world WF attack on single-path observers.

Input: a wf_dataset.sh output directory. For every config it cuts the two
per-path captures into visits (visits_<cfg>.csv windows) and builds three
traces per visit:
  full  path A + path B merged by time  (= what a single-path tunnel leaks)
  A, B  what an observer on that one path records
Each packet is (time, signed size): + client->server, - server->client.

Attack: k-FP-style hand-crafted features (counts, sizes, timing, bursts,
first/last-30, per-100ms rate, CUMUL interpolation, RF-style TAM counts in
44 ms slots) and a Random Forest. Stratified 5-fold CV over visits.

Scenarios per config (accuracy over 30 classes; chance = 1/30):
  full          attacker sees the whole trace (no split)
  A, B          adaptive attacker trained and tested on that path's traces
  pooled->A     trained on BOTH paths' sub-traces of the training visits
                (TrafficSliver's strongest training strategy), tested on A
  naive->A      trained on full traces, tested on A (attacker ignores split)

  python3 wf_eval.py <dataset-dir> [--configs wlb,equal,bwr,rand] [--out res.json]
"""
import argparse
import csv
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_split import read_pcap, ip_payload, parse_udp  # noqa: E402

CLIENT_IPS = {"192.168.10.1", "192.168.20.1"}
TAM_SLOT, TAM_SLOTS = 0.044, 60          # first 2.64 s
CUMUL_N = 50


def load_pcap(path):
    ts, sz = [], []
    for t, orig, lt, data in read_pcap(path):
        u = parse_udp(ip_payload(lt, data))
        if not u or 4433 not in (u[2], u[3]):
            continue
        ts.append(t)
        sz.append(orig if u[0] in CLIENT_IPS else -orig)
    return np.array(ts), np.array(sz)


def cut(ts, sz, t0, t1):
    i, j = np.searchsorted(ts, t0), np.searchsorted(ts, t1)
    return ts[i:j], sz[i:j]


def bursts(sz):
    if len(sz) == 0:
        return np.array([0]), np.array([0])
    d = np.sign(sz)
    edges = np.flatnonzero(np.diff(d)) + 1
    parts = np.split(np.arange(len(sz)), edges)
    return np.array([len(p) for p in parts]), np.array([np.abs(sz[p]).sum() for p in parts])


def stats(x):
    if len(x) == 0:
        return [0, 0, 0, 0, 0]
    return [float(np.mean(x)), float(np.std(x)), float(np.max(x)),
            float(np.percentile(x, 50)), float(np.percentile(x, 90))]


def feats(ts, sz):
    if len(ts) == 0:
        return np.zeros(FEAT_LEN)
    t = ts - ts[0]
    inc, out = sz < 0, sz > 0
    f = [len(sz), inc.sum(), out.sum(), -sz[inc].sum(), sz[out].sum(),
         inc.mean(), t[-1]]
    f += stats(np.diff(t)) + stats(np.diff(t[inc])) + stats(np.diff(t[out]))
    f += stats(np.abs(sz[inc])) + stats(sz[out])
    bl, bb = bursts(sz)
    f += [len(bl)] + stats(bl) + stats(bb)
    f += [inc[:30].sum(), out[:30].sum(), inc[-30:].sum(), out[-30:].sum()]
    nb = max(1, int(np.ceil(t[-1] / 0.1)))
    rate = np.bincount(np.minimum((t / 0.1).astype(int), nb - 1), minlength=nb)
    f += stats(rate) + [nb]
    cs = np.cumsum(sz)
    f += list(np.interp(np.linspace(0, len(cs) - 1, CUMUL_N), np.arange(len(cs)), cs))
    slot = (t / TAM_SLOT).astype(int)
    keep = slot < TAM_SLOTS
    f += list(np.bincount(slot[keep & inc], minlength=TAM_SLOTS)[:TAM_SLOTS])
    f += list(np.bincount(slot[keep & out], minlength=TAM_SLOTS)[:TAM_SLOTS])
    return np.array(f, dtype=float)


FEAT_LEN = len(feats(np.array([0.0, 0.01]), np.array([100, -1200])))


def build(dirpath, cfg):
    ta, sa = load_pcap(os.path.join(dirpath, f"pcap_{cfg}_A.pcap"))
    tb, sb = load_pcap(os.path.join(dirpath, f"pcap_{cfg}_B.pcap"))
    rows = list(csv.DictReader(open(os.path.join(dirpath, f"visits_{cfg}.csv"))))
    X = {"full": [], "A": [], "B": []}
    y, share = [], []
    for r in rows:
        if int(r["bytes"]) < 0:
            continue
        t0, t1 = float(r["t_start"]) - 0.05, float(r["t_end"]) + 0.3
        a_t, a_s = cut(ta, sa, t0, t1)
        b_t, b_s = cut(tb, sb, t0, t1)
        m_t = np.concatenate([a_t, b_t]); m_s = np.concatenate([a_s, b_s])
        o = np.argsort(m_t, kind="stable")
        X["full"].append(feats(m_t[o], m_s[o]))
        X["A"].append(feats(a_t, a_s))
        X["B"].append(feats(b_t, b_s))
        dn_a, dn_b = -a_s[a_s < 0].sum(), -b_s[b_s < 0].sum()
        share.append(dn_a / max(1, dn_a + dn_b))
        y.append(int(r["site"]))
    return {k: np.array(v) for k, v in X.items()}, np.array(y), np.array(share)


def rf():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=400, n_jobs=-1, random_state=0)


def evaluate(X, y, folds=5):
    from sklearn.model_selection import StratifiedKFold
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=0)
    res = {k: [] for k in ("full", "A", "B", "pooled->A", "naive->A")}
    for tr, te in skf.split(X["full"], y):
        for k in ("full", "A", "B"):
            m = rf().fit(X[k][tr], y[tr])
            res[k].append(float(np.mean(m.predict(X[k][te]) == y[te])))
        m = rf().fit(np.vstack([X["A"][tr], X["B"][tr]]), np.concatenate([y[tr], y[tr]]))
        res["pooled->A"].append(float(np.mean(m.predict(X["A"][te]) == y[te])))
        m = rf().fit(X["full"][tr], y[tr])
        res["naive->A"].append(float(np.mean(m.predict(X["A"][te]) == y[te])))
    return {k: (float(np.mean(v)), float(np.std(v))) for k, v in res.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--configs", default="wlb,equal,bwr,rand")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = {}
    print("config,visits,share_A_mean,share_A_std," +
          ",".join(f"{k}_acc" for k in ("full", "A", "B", "pooled->A", "naive->A")))
    for cfg in a.configs.split(","):
        if not os.path.exists(os.path.join(a.dir, f"visits_{cfg}.csv")):
            continue
        X, y, share = build(a.dir, cfg)
        r = evaluate(X, y)
        out[cfg] = {"visits": int(len(y)), "classes": int(len(set(y.tolist()))),
                    "share_A_mean": float(share.mean()), "share_A_std": float(share.std()),
                    "acc": r}
        print(f"{cfg},{len(y)},{share.mean():.3f},{share.std():.3f}," +
              ",".join(f"{r[k][0]:.3f}±{r[k][1]:.3f}" for k in ("full", "A", "B", "pooled->A", "naive->A")),
              flush=True)
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
