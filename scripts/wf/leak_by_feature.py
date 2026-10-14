#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
leak_by_feature.py -- which feature groups survive splitting?

For each config of a wf_dataset.sh directory, trains a Random Forest on ONE
feature group at a time and reports closed-world accuracy on the full trace
and on the single-path observer A (adaptive: trained on A traces). A group
that keeps most of its full-trace accuracy on A is a leak the split does not
hide. Scale-free groups (normalised histograms / shapes / ratios) are
unaffected by the per-page share by construction.

Also tests "gap interpolation": the observer estimates the page's TOTAL
download volume from its own bytes divided by the fraction of the load time
its path was active (gaps = the other path's runs), and compares how well
that tracks the true total versus its own bytes alone.

  python3 leak_by_feature.py <dataset-dir> [--configs equal,bwr,rand]
"""
import argparse
import csv
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wf_eval as W  # noqa: E402

SLOT, NSLOT = 0.044, 60


def groups(ts, sz):
    g = {}
    if len(ts) < 2:
        ts = np.array([0.0, 0.001]); sz = np.array([1, -1])
    t = ts - ts[0]
    inc, out = sz < 0, sz > 0
    a = np.abs(sz)
    g["volume (counts, bytes)"] = [len(sz), inc.sum(), out.sum(), a[inc].sum(), a[out].sum()]
    hi = np.histogram(a[inc], bins=30, range=(0, 1500))[0]
    ho = np.histogram(a[out], bins=10, range=(0, 1500))[0]
    g["packet-size histogram (normalised)"] = list(hi / max(1, hi.sum())) + list(ho / max(1, ho.sum()))
    g["in/out ratios"] = [inc.mean(), a[inc].sum() / max(1, a.sum()),
                          a[inc].mean() if inc.any() else 0, a[out].mean() if out.any() else 0]
    g["duration & inter-arrival"] = [t[-1]] + W.stats(np.diff(t)) + W.stats(np.diff(t[inc])) \
        + W.stats(np.diff(t[out]))
    slot = (t / SLOT).astype(int); keep = slot < NSLOT
    ti = np.bincount(slot[keep & inc], minlength=NSLOT)[:NSLOT].astype(float)
    to = np.bincount(slot[keep & out], minlength=NSLOT)[:NSLOT].astype(float)
    g["rate envelope (TAM, normalised shape)"] = list(ti / max(1, ti.sum())) + list(to / max(1, to.sum()))
    bl, bb = W.bursts(sz)
    g["bursts"] = [len(bl)] + W.stats(bl) + W.stats(bb)
    first = np.zeros(60); k = min(30, len(sz))
    first[:k] = np.sign(sz[:k]); first[30:30 + k] = a[:k]
    g["first 30 packets"] = list(first)
    return {k: np.array(v, dtype=float) for k, v in g.items()}


def build(dirpath, cfg):
    ta, sa = W.load_pcap(os.path.join(dirpath, f"pcap_{cfg}_A.pcap"))
    tb, sb = W.load_pcap(os.path.join(dirpath, f"pcap_{cfg}_B.pcap"))
    rows = [r for r in csv.DictReader(open(os.path.join(dirpath, f"visits_{cfg}.csv")))
            if int(r["bytes"]) >= 0]
    full, A, y, gap = [], [], [], []
    for r in rows:
        t0, t1 = float(r["t_start"]) - 0.05, float(r["t_end"]) + 0.3
        a_t, a_s = W.cut(ta, sa, t0, t1); b_t, b_s = W.cut(tb, sb, t0, t1)
        m_t = np.concatenate([a_t, b_t]); m_s = np.concatenate([a_s, b_s])
        o = np.argsort(m_t, kind="stable")
        full.append(groups(m_t[o], m_s[o])); A.append(groups(a_t, a_s)); y.append(int(r["site"]))
        # gap interpolation on A's download packets
        d_t = a_t[a_s < 0]; own = -a_s[a_s < 0].sum()
        tot = own - b_s[b_s < 0].sum()
        mt = m_t[o][m_s[o] < 0]
        if len(d_t) >= 3 and len(mt) >= 3:
            iat = np.diff(d_t); thr = 5 * np.median(np.diff(mt))       # "silent" = 5x the page's packet spacing
            active = iat[iat <= thr].sum(); dur = mt[-1] - mt[0]
            frac = min(1.0, max(0.02, active / dur)) if dur > 0 else 1.0
            gap.append((own, own / frac, tot))
    return full, A, np.array(y), np.array(gap)


def acc(X, y):
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    skf = StratifiedKFold(5, shuffle=True, random_state=0)
    return float(np.mean(cross_val_score(W.rf(), X, y, cv=skf)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--configs", default="equal,bwr,rand")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = {}
    for cfg in a.configs.split(","):
        full, A, y, gap = build(a.dir, cfg)
        res = {}
        for gname in full[0]:
            Xf = np.array([f[gname] for f in full]); Xa = np.array([f[gname] for f in A])
            res[gname] = (acc(Xf, y), acc(Xa, y))
            print(f"{cfg:6s} {gname:40s} full={res[gname][0]:.3f}  pathA={res[gname][1]:.3f}", flush=True)
        own, est, tot = np.log(gap[:, 0] + 1), np.log(gap[:, 1] + 1), np.log(gap[:, 2] + 1)
        c_own = float(np.corrcoef(own, tot)[0, 1]); c_est = float(np.corrcoef(est, tot)[0, 1])
        err_own = float(np.median(np.abs(np.exp(own - tot) - 1)))
        err_est = float(np.median(np.abs(np.exp(est - tot) - 1)))
        print(f"{cfg:6s} gap interpolation: corr(log own bytes, log total)={c_own:.3f} -> "
              f"corr(log estimate, log total)={c_est:.3f}; median |error| {err_own:.0%} -> {err_est:.0%}")
        out[cfg] = {"groups": res, "gap": {"corr_own": c_own, "corr_est": c_est,
                                           "med_err_own": err_own, "med_err_est": err_est}}
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
