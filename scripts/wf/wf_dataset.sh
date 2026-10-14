#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# wf_dataset.sh -- collect a closed-world split-traffic dataset per scheduler.
#
# Same two-path netns topology as wf_split_measure.sh (path A, path B, both
# shaped with tbf), inner TCP on the hybrid stream lane. For every config it
# captures both client-side interfaces for the whole session (pcap_<cfg>_A/B)
# while wf_sites.py loads SITES x VISITS synthetic page loads, logging each
# visit's time window (visits_<cfg>.csv). The server writes its scheduler's
# per-packet decisions (decisions_<cfg>.log) when the scheduler is wfsplit.
#
# Usage: sudo ./wf_dataset.sh [mqvpn] [outdir]
#   SITES=30 VISITS=12 RATE_A=50mbit RATE_B=50mbit
#   CONFIGS_OVERRIDE=$'label|scheduler|env'  (newline separated)

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="$(realpath "${1:-${SCRIPT_DIR}/../../build/mqvpn}")"
OUT="$(realpath -m "${2:-$(pwd)/wf_dataset}")"
SITES="${SITES:-30}" VISITS="${VISITS:-12}"
RATE_A="${RATE_A:-50mbit}" RATE_B="${RATE_B:-50mbit}"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
PSK=$("$MQVPN" --genkey 2>/dev/null)

CONFIGS=(
  "wlb|wlb|"
  "equal|wfsplit|MQVPN_WFS_POLICY=equal"
  "bwr|wfsplit|MQVPN_WFS_POLICY=bwr"
  "rand|wfsplit|MQVPN_WFS_POLICY=rand"
)
if [ -n "${CONFIGS_OVERRIDE:-}" ]; then mapfile -t CONFIGS <<< "$CONFIGS_OVERRIDE"; fi

PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null
    ip netns del wfs-server 2>/dev/null; ip netns del wfs-client 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

ip netns del wfs-server 2>/dev/null; ip netns del wfs-client 2>/dev/null
ip netns add wfs-server; ip netns add wfs-client
for p in a:10:$RATE_A b:20:$RATE_B; do
    IFS=: read -r n net rate <<< "$p"
    ip link add wfs-${n}0 type veth peer name wfs-${n}1
    ip link set wfs-${n}0 netns wfs-client; ip link set wfs-${n}1 netns wfs-server
    ip netns exec wfs-client ip addr add 192.168.${net}.1/24 dev wfs-${n}0
    ip netns exec wfs-server ip addr add 192.168.${net}.2/24 dev wfs-${n}1
    ip netns exec wfs-client ip link set wfs-${n}0 up; ip netns exec wfs-server ip link set wfs-${n}1 up
    ip netns exec wfs-client tc qdisc add dev wfs-${n}0 root tbf rate "$rate" burst 64kb latency 200ms
    ip netns exec wfs-server tc qdisc add dev wfs-${n}1 root tbf rate "$rate" burst 64kb latency 200ms
done
ip netns exec wfs-client ip link set lo up; ip netns exec wfs-server ip link set lo up
ip netns exec wfs-server ip addr add 10.0.5.1/32 dev lo
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$WORK/k" \
    -out "$WORK/c" -days 1 -nodes -subj /CN=wfs 2>/dev/null
printf '[Hybrid]\nEnabled = true\nEgressAllow = 10.0.5.0/24\n' > "$WORK/s.conf"
printf '[Hybrid]\nEnabled = true\nTcp = stream\n' > "$WORK/c.conf"

for cfg in "${CONFIGS[@]}"; do
    IFS='|' read -r label sched envs <<< "$cfg"
    echo "=== $label ($sched $envs) ==="
    rm -f "$OUT/decisions_${label}.log"
    env $envs MQVPN_WFS_DECISION_LOG="$OUT/decisions_${label}.log" \
        ip netns exec wfs-server "$MQVPN" --config "$WORK/s.conf" --mode server \
        --listen 0.0.0.0:4433 --subnet 10.0.0.0/24 --cert "$WORK/c" --key "$WORK/k" \
        --auth-key "$PSK" --scheduler "$sched" --log-level info > "$OUT/log_${label}_server.txt" 2>&1 &
    SP=$!
    sleep 1.5
    env $envs ip netns exec wfs-client "$MQVPN" --config "$WORK/c.conf" --mode client \
        --server 192.168.10.2:4433 --path wfs-a0 --path wfs-b0 --auth-key "$PSK" --insecure \
        --scheduler "$sched" --log-level info > "$OUT/log_${label}_client.txt" 2>&1 &
    CP=$!
    for _ in $(seq 1 20); do sleep 0.5; ip netns exec wfs-client ping -c1 -W1 10.0.0.1 >/dev/null 2>&1 && break; done
    sleep 3
    ip netns exec wfs-client ip route replace 10.0.5.0/24 dev mqvpn0
    ip netns exec wfs-server python3 "$SCRIPT_DIR/pageload.py" server --bind 10.0.5.1 --port 8080 &
    AP=$!
    ip netns exec wfs-client tcpdump -i wfs-a0 -s 96 -w "$OUT/pcap_${label}_A.pcap" udp port 4433 2>/dev/null &
    T1=$!
    ip netns exec wfs-client tcpdump -i wfs-b0 -s 96 -w "$OUT/pcap_${label}_B.pcap" udp port 4433 2>/dev/null &
    T2=$!
    PIDS=($SP $CP $AP $T1 $T2)
    sleep 1
    ip netns exec wfs-client python3 "$SCRIPT_DIR/wf_sites.py" --server 10.0.5.1 \
        --sites "$SITES" --visits "$VISITS" --log "$OUT/visits_${label}.csv"
    sleep 1
    kill $T1 $T2; sleep 0.5; kill $AP $CP $SP 2>/dev/null; wait 2>/dev/null
    PIDS=()
    sleep 1
done
echo done
