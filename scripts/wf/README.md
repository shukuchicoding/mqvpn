# wfsplit — traffic splitting for website-fingerprinting defense research

`wfsplit` is a multipath scheduler (in the xquic fork,
`src/transport/scheduler/xqc_scheduler_wfsplit.c`) that splits tunnel
traffic across paths so that an observer on one access path does not record
the whole page load. Unlike `wlb` it never pins an inner flow to a path and
never weights paths by measured goodput.

## Running it

Both ends must run it: the client's scheduler places upload packets, the
server's places download packets (where most page bytes are).

```bash
# server
mqvpn --mode server ... --scheduler wfsplit
# client
mqvpn --mode client ... --path eth0 --path wlan0 --scheduler wfsplit
```

Or set `Scheduler = wfsplit` in `[Multipath]`. A client can also ask the
server for it per connection (`RequestServerScheduler = true` on the client,
`AllowClientScheduler = true` on the server); the env knobs are still read
from the server process environment.

| Variable | Values (default first) | Meaning |
|---|---|---|
| `MQVPN_WFS_POLICY` | `rand`, `bwr`, `equal` | split policy (below) |
| `MQVPN_WFS_ON_BLOCK` | `wait`, `spill` | chosen path cwnd-full: wait for it (exact split) or use another path (throughput, split drifts toward capacity) |
| `MQVPN_WFS_UNIT` | `bytes`, `packets` | what `equal` balances |
| `MQVPN_WFS_RUN_MEAN_MIN` / `_MAX` | `10` / `50` | `rand`: per-page mean run length is drawn from this range, packets |
| `MQVPN_WFS_BATCH_MIN` / `_MAX` | `50` / `70` | `bwr` batch length, packets |
| `MQVPN_WFS_RESAMPLE_IDLE_MS` | `1000` | `rand`/`bwr`: redraw weights after this idle gap (≈ new page); `0` = off |
| `MQVPN_WFS_RESAMPLE_MS` | `0` | `rand`/`bwr`: also redraw every N ms; `0` = off |
| `MQVPN_WFS_SEED` | unset (CSPRNG) | seeded xorshift for reproducible tests only; never deploy with it |
| `MQVPN_WFS_DECISION_LOG` | unset | append `t_us,path_id,bytes` per scheduled packet to this file |

Policies:

- `rand` (default): HyWF-style random runs. Per page the path weights are
  drawn from a flat Dirichlet and a mean run length `m` from the range above;
  runs are geometric with mean `m`, each run's path drawn from the weights.
  Geometric runs are memoryless, so the history of assignments does not
  predict the next switch.
- `bwr`: TrafficSliver's Batched Weighted Random, batches of
  U[`BATCH_MIN`, `BATCH_MAX`] packets. The bounded batch length is learnable
  (a switch becomes certain once a batch reaches `BATCH_MAX`).
- `equal`: baseline only, not a defense. Lowest byte credit wins, which for
  similar packet sizes is alternation (round robin): each observer sees a fixed
  half of the trace.

All randomness comes from BoringSSL's `RAND_bytes` unless `MQVPN_WFS_SEED` is
set. `split_predictability.py` measures how learnable a policy's assignment
sequence is from decision logs; `wf_dataset.sh` + `wf_eval.py` run a
closed-world WF attack against single-path observers.

The scheduler logs `|wfsplit|init|...` once per connection and
`|wfsplit|stats|...` (per-path bytes, packets, share) about once a second at
info level.

## Adding your own policy

Write `wfs_pick_<name>(s, n, cand_slot, exclude, ...)` returning the index of
the candidate path a packet should take (ignoring cwnd), add it to
`wfs_policy_t`, `wfs_pick()` and `wfs_load_config()`. Health checks, cwnd
wait/spill, reinjection and accounting are handled around it.

What the policy can see per packet: `packet_out->po_used_size`,
`po_frame_types` (STREAM / DATAGRAM / control), `po_flow_hash` (inner
5-tuple hash on the datagram lane), the clock, and per-path congestion state
through `path->path_send_ctl`. It cannot create packets: cover traffic has to
be injected by mqvpn (e.g. next to `tun_send_datagram`) and dropped by the
peer.

## Things that leak around the scheduler

- Packets bound to a path before scheduling never reach it: ACK_MP frames go
  back on the path they acknowledge (keep xquic's `mp_ack_on_any_path = 0`,
  otherwise one path's ACK rate reveals the other's download), PATH_CHALLENGE /
  RESPONSE, PTO probes, keep-alive PINGs.
- Reinjection (`[Multipath] Reinjection`) copies packets onto the other
  path; keep it `off` for WF experiments.
- Packet sizes are not padded: each tunnel packet is the inner packet plus a
  fixed overhead.
- Per-packet splitting of inner TCP over unequal paths reorders it. On the
  datagram lane inner TCP then retransmits heavily (wire bytes ≈ 2× payload in
  the 50/20 Mbit test). Run inner TCP over the hybrid stream lane
  (`[Hybrid] Enabled = true`, `Tcp = stream`; server `EgressAllow`), where QUIC
  absorbs the reordering.

## Measuring the split

`wf_split_measure.sh` builds two shaped paths with network namespaces, runs
page loads, a bulk download and a UDP flow under each scheduler config, and
writes per-path byte counts (`split.csv`) plus per-observer traces of one page
load (`trace_*.csv`, columns `t_rel,path,dir,wire_len`).
`summarize.py <outdir>` prints the summary and draws the figures.

```bash
sudo REPS=10 scripts/wf/wf_split_measure.sh build/mqvpn /tmp/wfs
python3 scripts/wf/summarize.py /tmp/wfs
```
