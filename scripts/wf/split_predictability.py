#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
split_predictability.py -- can the path assignment itself be learned?

Input: decision logs written by wfsplit (MQVPN_WFS_DECISION_LOG), one line
per scheduled packet "t_us,path_id,bytes". Pages are cut at idle gaps.

For each log it reports:
  share      per-page fraction of packets on path 0 (spread = volume ambiguity)
  switch     P(next packet changes path)
  hazard     P(switch | current run has lasted k packets), k = 1..120:
             flat = memoryless (unpredictable), spikes/ramps = learnable rule
  ml_acc     accuracy of a gradient-boosted classifier predicting the next
             packet's path from the previous 32 assignments, the current run
             length, recent packet sizes and inter-send gaps -- trained on
             70% of pages, tested on the rest
  persist    accuracy of the trivial rule "same path as the previous packet"
  ml_gain    ml_acc - persist: what a model learns beyond persistence.
  switch_auc ROC AUC of a model predicting WHETHER the next packet switches
             path (same features). Accuracy is misleading when switches are
             rare; AUC is not. 0.5 = the history says nothing about when the
             next switch comes (memoryless); near 1 = the rule is learnable.

  python3 split_predictability.py --out stats.json decisions_equal.log ...
"""
import argparse
import json
import sys

import numpy as np

K_HIST = 32
GAP_US = 1_000_000


def load(path):
    t, p, b = [], [], []
    with open(path) as f:
        for line in f:
            if line.startswith("#"):
                continue
            x = line.strip().split(",")
            if len(x) != 3:
                continue
            t.append(int(x[0])); p.append(int(x[1])); b.append(int(x[2]))
    t = np.array(t, dtype=np.int64); p = np.array(p); b = np.array(b)
    ids = sorted(set(p.tolist()))
    lab = np.array([ids.index(v) for v in p])      # 0/1 for two paths
    return t, lab, b


def pages(t):
    cut = np.where(np.diff(t) > GAP_US)[0] + 1
    return np.split(np.arange(len(t)), cut)


def run_lengths(lab):
    runs, cur = [], 1
    for i in range(1, len(lab)):
        if lab[i] == lab[i - 1]:
            cur += 1
        else:
            runs.append(cur); cur = 1
    runs.append(cur)
    return runs


def hazard(seqs, kmax=120):
    # P(switch after position k of a run | run reached k)
    reach = np.zeros(kmax + 2); sw = np.zeros(kmax + 2)
    for lab in seqs:
        runs = run_lengths(lab)
        for r in runs[:-1]:                         # last run is censored
            for k in range(1, min(r, kmax) + 1):
                reach[k] += 1
            if r <= kmax:
                sw[r] += 1
    h = np.where(reach > 0, sw / np.maximum(reach, 1), np.nan)
    return h[1:kmax + 1], reach[1:kmax + 1]


def features(lab, b, t):
    X, y = [], []
    n = len(lab)
    run = 1
    for i in range(K_HIST, n - 1):
        if lab[i] == lab[i - 1]:
            run += 1
        else:
            run = 1
        hist = lab[i - K_HIST + 1:i + 1]
        sizes = b[i - 3:i + 1]
        gaps = np.diff(t[i - 3:i + 1])
        X.append(np.concatenate([hist, [run, min(run, 200)], sizes, gaps, [b[i + 1]]]))
        y.append(lab[i + 1])
    return X, y


def analyse(path):
    t, lab, b = load(path)
    pg = [ix for ix in pages(t) if len(ix) >= 2 * K_HIST]
    shares = [float(np.mean(lab[ix] == 0)) for ix in pg]
    seqs = [lab[ix] for ix in pg]
    allsw = np.concatenate([np.diff(s) != 0 for s in seqs])
    h, reach = hazard(seqs)

    # train/test split by page
    rng = np.random.default_rng(1)
    order = rng.permutation(len(pg))
    ntr = int(0.7 * len(pg))
    tr, te = order[:ntr], order[ntr:]
    Xtr, ytr, Xte, yte = [], [], [], []
    for j in tr:
        x, y = features(lab[pg[j]], b[pg[j]], t[pg[j]]); Xtr += x; ytr += y
    for j in te:
        x, y = features(lab[pg[j]], b[pg[j]], t[pg[j]]); Xte += x; yte += y
    from sklearn.ensemble import HistGradientBoostingClassifier
    clf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1)
    clf.fit(np.array(Xtr), np.array(ytr))
    pred = clf.predict(np.array(Xte))
    yte = np.array(yte)
    Xte = np.array(Xte)
    acc = float(np.mean(pred == yte))
    persist = float(np.mean(Xte[:, K_HIST - 1] == yte))
    # switch / no-switch model
    from sklearn.metrics import roc_auc_score
    Xtr_a = np.array(Xtr)
    str_ = (np.array(ytr) != Xtr_a[:, K_HIST - 1]).astype(int)
    ste = (yte != Xte[:, K_HIST - 1]).astype(int)
    if 0 < str_.sum() < len(str_) and 0 < ste.sum() < len(ste):
        sclf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1)
        sclf.fit(Xtr_a, str_)
        auc = float(roc_auc_score(ste, sclf.predict_proba(Xte)[:, 1]))
    else:
        auc = float("nan")
    runs = [r for s in seqs for r in run_lengths(s)[:-1]]
    return {
        "file": path, "packets": int(len(lab)), "pages": len(pg),
        "share_p0_mean": float(np.mean(shares)), "share_p0_std": float(np.std(shares)),
        "share_p0_min": float(np.min(shares)), "share_p0_max": float(np.max(shares)),
        "p_switch": float(np.mean(allsw)),
        "run_len_mean": float(np.mean(runs)), "run_len_p10_p90":
            [float(np.percentile(runs, 10)), float(np.percentile(runs, 90))],
        "hazard": [None if np.isnan(x) else round(float(x), 4) for x in h],
        "hazard_support": [int(x) for x in reach],
        "ml_acc": acc, "persist_acc": persist, "ml_gain": acc - persist,
        "switch_auc": auc,
        "test_samples": int(len(yte)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=None)
    ap.add_argument("logs", nargs="+")
    a = ap.parse_args()
    res = [analyse(p) for p in a.logs]
    for r in res:
        print(f"{r['file']}: pages={r['pages']} pkts={r['packets']} "
              f"share_p0={r['share_p0_mean']:.3f}±{r['share_p0_std']:.3f} "
              f"[{r['share_p0_min']:.2f},{r['share_p0_max']:.2f}] "
              f"p_switch={r['p_switch']:.4f} run_mean={r['run_len_mean']:.1f} "
              f"ml_acc={r['ml_acc']:.4f} persist={r['persist_acc']:.4f} "
              f"gain={r['ml_gain']:+.4f} switch_auc={r['switch_auc']:.3f}")
    if a.out:
        json.dump(res, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
