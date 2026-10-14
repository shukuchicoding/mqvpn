#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
summarize.py -- summary table + figures for wf_split_measure.sh output.

  python3 summarize.py <results-dir>

Prints, per scenario x config: the per-page download share on path A
(mean, std, min, max over page loads), the bulk-transfer share and rate, the
UDP share, and wire-bytes / payload-bytes for page loads (inflation from
inner retransmissions). Writes, when matplotlib is available:
  fig_page_share.png   per-page share of download bytes on path A
  fig_observer.png     what each single-path observer records during one
                       page load (download bytes per 20 ms, path A up, B down)
"""
import csv
import os
import statistics as st
import sys

PAGE_BYTES = 2301000          # default PAGE_SPEC total payload
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
PATH_A, PATH_B = "#2a78d6", "#eb6834"   # categorical slots 1 and 2


def load(dirpath):
    rows = list(csv.DictReader(open(os.path.join(dirpath, "split.csv"))))
    order, data = [], {}
    for r in rows:
        key = (r["scenario"], r["config"])
        if key not in data:
            data[key] = {"page": [], "page_bytes": [], "page_s": []}
            order.append(key)
        d = data[key]
        if r["workload"].startswith("page"):
            d["page"].append(float(r["down_share_a"]))
            d["page_bytes"].append(int(r["down_a"]) + int(r["down_b"]))
            s = r["result"].split(":")[-1]
            if s not in ("ERR", ""):
                d["page_s"].append(float(s))
        elif r["workload"] == "bulk":
            d["bulk"] = (float(r["down_share_a"]), r["result"].split(":")[-1],
                         int(r["down_a"]) + int(r["down_b"]))
        elif r["workload"] == "udp":
            d["udp"] = float(r["down_share_a"])
    return order, data


def table(order, data):
    hdr = ("scenario", "config", "page_A_mean", "page_A_std", "page_A_min",
           "page_A_max", "page_s", "wire/payload", "bulk_A", "bulk_mbps",
           "bulk_wire_MB", "udp_A")
    print(",".join(hdr))
    for key in order:
        d = data[key]
        p = d["page"]
        sd = st.pstdev(p) if len(p) > 1 else 0.0
        infl = st.mean(d["page_bytes"]) / PAGE_BYTES if d["page_bytes"] else 0
        ps = st.mean(d["page_s"]) if d["page_s"] else float("nan")
        b = d.get("bulk", (float("nan"), "", 0))
        print(f"{key[0]},{key[1]},{st.mean(p):.3f},{sd:.3f},{min(p):.3f},{max(p):.3f},"
              f"{ps:.2f},{infl:.2f},{b[0]:.3f},{b[1]},{b[2]/1e6:.1f},{d.get('udp', float('nan')):.3f}")


def style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=8)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def fig_page_share(order, data, out):
    import matplotlib.pyplot as plt
    scen = [s for s in dict.fromkeys(k[0] for k in order)]
    fig, axes = plt.subplots(1, len(scen), figsize=(5.2 * len(scen), 3.6),
                             sharey=True, facecolor=SURFACE)
    if len(scen) == 1:
        axes = [axes]
    for ax, sc in zip(axes, scen):
        style(ax)
        cfgs = [k[1] for k in order if k[0] == sc]
        ax.axhline(0.5, color=INK2, linewidth=1, linestyle=(0, (3, 3)))
        for i, c in enumerate(cfgs):
            p = data[(sc, c)]["page"]
            xs = [i + (j - (len(p) - 1) / 2) * 0.035 for j in range(len(p))]
            ax.scatter(xs, p, s=22, color=PATH_A, edgecolors=SURFACE,
                       linewidths=1, zorder=3)
        ax.set_xticks(range(len(cfgs)))
        ax.set_xticklabels(cfgs, rotation=35, ha="right", color=INK)
        ax.set_ylim(-0.02, 1.02)
        ax.set_title(f"{sc} links", color=INK, fontsize=10, loc="left")
    axes[0].set_ylabel("share of page download on path A", color=INK2, fontsize=9)
    fig.suptitle("Per-page split, one dot per page load (dashed = even split)",
                 color=INK, fontsize=11, x=0.01, ha="left")
    fig.tight_layout()
    fig.savefig(out, dpi=160, facecolor=SURFACE)


def load_trace(path):
    rows = []
    with open(path) as f:
        next(f)
        for line in f:
            t, p, d, ln = line.strip().split(",")
            rows.append((float(t), int(p), int(d), int(ln)))
    return rows


def fig_observer(dirpath, scen, configs, out, bin_s=0.02):
    import matplotlib.pyplot as plt
    avail = [c for c in configs
             if os.path.exists(os.path.join(dirpath, f"trace_{scen}_{c}.csv"))]
    if not avail:
        return
    fig, axes = plt.subplots(len(avail), 1, figsize=(7.5, 1.9 * len(avail)),
                             sharex=True, facecolor=SURFACE)
    if len(avail) == 1:
        axes = [axes]
    tmax = 0
    peak = 1
    series = {}
    for c in avail:
        rows = [r for r in load_trace(os.path.join(dirpath, f"trace_{scen}_{c}.csv")) if r[2] < 0]
        t0 = rows[0][0] if rows else 0
        nb = int(max((r[0] - t0 for r in rows), default=0) / bin_s) + 1
        a, b = [0] * nb, [0] * nb
        for t, p, d, ln in rows:
            k = int((t - t0) / bin_s)
            (a if p == 0 else b)[k] += ln
        series[c] = (a, b)
        tmax = max(tmax, nb * bin_s)
        peak = max(peak, max(a + b, default=1))
    for ax, c in zip(axes, avail):
        style(ax)
        a, b = series[c]
        xs = [i * bin_s for i in range(len(a))]
        ax.bar(xs, [v / 1e3 for v in a], width=bin_s * 0.9, align="edge",
               color=PATH_A, label="observer on path A")
        ax.bar(xs, [-v / 1e3 for v in b], width=bin_s * 0.9, align="edge",
               color=PATH_B, label="observer on path B")
        ax.axhline(0, color=INK2, linewidth=0.8)
        lim = peak / 1e3 * 1.1
        ax.set_ylim(-lim, lim)
        ax.set_xlim(0, tmax)
        tot = sum(a) + sum(b) or 1
        ax.set_title(f"{c}   (A sees {sum(a)/tot:.0%}, B sees {sum(b)/tot:.0%} of download bytes)",
                     color=INK, fontsize=9, loc="left")
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{abs(v):.0f}"))
    axes[0].legend(loc="upper right", fontsize=8, frameon=False, labelcolor=INK2)
    axes[-1].set_xlabel("time since first packet (s)", color=INK2, fontsize=9)
    fig.text(0.005, 0.5, "KB per 20 ms (A up, B down)", rotation=90, va="center",
             color=INK2, fontsize=9)
    fig.suptitle(f"One page load as seen on each path ({scen} links)", color=INK,
                 fontsize=11, x=0.01, ha="left")
    fig.tight_layout(rect=(0.02, 0, 1, 1))
    fig.savefig(out, dpi=160, facecolor=SURFACE)


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "wf_split_results"
    order, data = load(d)
    table(order, data)
    try:
        import matplotlib
        matplotlib.use("Agg")
    except ImportError:
        print("(matplotlib not installed: skipping figures)", file=sys.stderr)
        return 0
    fig_page_share(order, data, os.path.join(d, "fig_page_share.png"))
    scen0 = order[0][0]
    fig_observer(d, scen0, ["wlb", "wlb+hybrid", "wfs-equal", "wfs-bwr+hybrid", "wfs-rand+hybrid"],
                 os.path.join(d, "fig_observer.png"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
