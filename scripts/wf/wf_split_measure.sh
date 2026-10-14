#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# wf_split_measure.sh -- how evenly does each scheduler split tunnel traffic
# across two paths, as seen by an observer on ONE path?
#
# Topology (network namespaces, no real NICs needed):
#
#   wfs-client  wfs-a0 ==(path A, tbf RATE_A)== wfs-a1  wfs-server
#               wfs-b0 ==(path B, tbf RATE_B)== wfs-b1      lo: 10.0.5.1 (web)
#
# For each scenario x scheduler config, runs inner workloads through the
# tunnel and records per-path bytes from the client's interface counters
# (rx = server->client "download", tx = client->server "upload"):
#   pageN  REPS synthetic page loads, one CSV row each (main object, then
#          sub-resources over 6 parallel TCP connections; idle gap between)
#   bulk   one 20 MB TCP download (one inner flow)
#   udp    iperf3 UDP download, 20 Mbit/s for 5 s (inner QUIC-like)
# Plus, for the first scenario, a pcap of ONE page load on each path, turned
# into per-observer traces by pcap_split.py.
#
# Usage: sudo ./wf_split_measure.sh [path-to-mqvpn] [outdir]
#   REPS=10                      page loads per config
#   CONFIGS_OVERRIDE=$'a|b|c|d'  run a subset (newline-separated config rows)
# Needs: iproute2 (ip, tc with tbf), iperf3, tcpdump, python3, openssl.
# Note: delay is not emulated (many sandboxes lack sch_netem); with netem,
#   replace the tbf line in apply_tc() by "netem delay Xms rate R".

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MQVPN="$(realpath "${1:-${SCRIPT_DIR}/../../build/mqvpn}")"
OUT="${2:-$(pwd)/wf_split_results}"
PAGELOAD="${SCRIPT_DIR}/pageload.py"
PCAPSPLIT="${SCRIPT_DIR}/pcap_split.py"
REPS="${REPS:-5}"
PAGE_SPEC="${PAGE_SPEC:-60000|180000,25000,40000,600000,9000,120000,30000,250000,15000,70000,5000,350000,45000,90000,12000,400000}"

mkdir -p "$OUT"
WORK="$(mktemp -d)"
PSK=$("$MQVPN" --genkey 2>/dev/null)
CSV="$OUT/split.csv"
echo "scenario,config,workload,down_a,down_b,down_share_a,up_a,up_b,up_share_a,result" > "$CSV"

SCENARIOS=("sym:50mbit:50mbit" "asym:50mbit:20mbit")
# label|scheduler|env|extras
#   env     space-separated KEY=VAL, applied to client AND server
#   extras  comma-separated:
#     hybrid   inner TCP rides the hybrid stream lane ([Hybrid] Enabled, Tcp=stream):
#              QUIC streams absorb per-packet reordering instead of inner TCP
#     reorder  mqvpn receive-side reorder buffer on the datagram lane
CONFIGS=(
  "wlb|wlb||"
  "minrtt|minrtt||"
  "wfs-equal|wfsplit|MQVPN_WFS_POLICY=equal|"
  "wfs-equal-spill|wfsplit|MQVPN_WFS_POLICY=equal MQVPN_WFS_ON_BLOCK=spill|"
  "wfs-bwr|wfsplit|MQVPN_WFS_POLICY=bwr MQVPN_WFS_RESAMPLE_IDLE_MS=1000|"
  "wlb+hybrid|wlb||hybrid"
  "wfs-equal+hybrid|wfsplit|MQVPN_WFS_POLICY=equal|hybrid"
  "wfs-bwr+hybrid|wfsplit|MQVPN_WFS_POLICY=bwr MQVPN_WFS_RESAMPLE_IDLE_MS=1000|hybrid"
  "wfs-rand+hybrid|wfsplit|MQVPN_WFS_POLICY=rand|hybrid"
)
if [ -n "${CONFIGS_OVERRIDE:-}" ]; then
    mapfile -t CONFIGS <<< "$CONFIGS_OVERRIDE"
fi

SERVER_PID="" CLIENT_PID="" APP_PID="" IPERF_PID=""
APP_IP=10.0.0.1

setup_netns() {
    ip netns del wfs-server 2>/dev/null; ip netns del wfs-client 2>/dev/null
    ip netns add wfs-server; ip netns add wfs-client
    for p in a:10 b:20; do
        local n=${p%%:*} net=${p##*:}
        ip link add wfs-${n}0 type veth peer name wfs-${n}1
        ip link set wfs-${n}0 netns wfs-client
        ip link set wfs-${n}1 netns wfs-server
        ip netns exec wfs-client ip addr add 192.168.${net}.1/24 dev wfs-${n}0
        ip netns exec wfs-server ip addr add 192.168.${net}.2/24 dev wfs-${n}1
        ip netns exec wfs-client ip link set wfs-${n}0 up
        ip netns exec wfs-server ip link set wfs-${n}1 up
    done
    ip netns exec wfs-client ip link set lo up
    ip netns exec wfs-server ip link set lo up
    # "Web server" outside the tunnel subnet: the hybrid lane refuses
    # tunnel-subnet destinations, so hybrid configs fetch from here.
    ip netns exec wfs-server ip addr add 10.0.5.1/32 dev lo
    ip netns exec wfs-server sysctl -qw net.ipv4.ip_forward=1
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$WORK/server.key" -out "$WORK/server.crt" -days 1 -nodes \
        -subj "/CN=wfs-test" 2>/dev/null
}

apply_tc() {
    local ra="$1" rb="$2"
    for side in "wfs-client wfs-a0 $ra" "wfs-server wfs-a1 $ra" \
                "wfs-client wfs-b0 $rb" "wfs-server wfs-b1 $rb"; do
        set -- $side
        ip netns exec "$1" tc qdisc del dev "$2" root 2>/dev/null
        ip netns exec "$1" tc qdisc add dev "$2" root tbf rate "$3" burst 64kb latency 200ms
    done
}

stop_vpn() {
    for p in $APP_PID $IPERF_PID $CLIENT_PID $SERVER_PID; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    APP_PID="" IPERF_PID="" CLIENT_PID="" SERVER_PID=""
    sleep 1
}

cleanup() {
    stop_vpn
    ip netns del wfs-server 2>/dev/null; ip netns del wfs-client 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

start_vpn() {
    local sched="$1" envs="$2" tag="$3" extras="$4"
    : > "$WORK/server.conf"; : > "$WORK/client.conf"
    APP_IP=10.0.0.1
    case ",$extras," in *,reorder,*)
        printf '[Reorder]\nEnabled = on\nMaxWaitMs = 50\nCapPackets = 1024\n' \
            | tee -a "$WORK/server.conf" >> "$WORK/client.conf" ;;
    esac
    case ",$extras," in *,hybrid,*)
        printf '[Hybrid]\nEnabled = true\nEgressAllow = 10.0.5.0/24\n' >> "$WORK/server.conf"
        printf '[Hybrid]\nEnabled = true\nTcp = stream\n' >> "$WORK/client.conf"
        APP_IP=10.0.5.1 ;;
    esac
    env $envs ip netns exec wfs-server "$MQVPN" --config "$WORK/server.conf" \
        --mode server --listen 0.0.0.0:4433 \
        --subnet 10.0.0.0/24 --cert "$WORK/server.crt" --key "$WORK/server.key" \
        --auth-key "$PSK" --scheduler "$sched" --log-level info \
        > "$OUT/log_${tag}_server.txt" 2>&1 &
    SERVER_PID=$!
    sleep 1.5
    env $envs ip netns exec wfs-client "$MQVPN" --config "$WORK/client.conf" \
        --mode client --server 192.168.10.2:4433 \
        --path wfs-a0 --path wfs-b0 --auth-key "$PSK" --insecure \
        --scheduler "$sched" --log-level info \
        > "$OUT/log_${tag}_client.txt" 2>&1 &
    CLIENT_PID=$!
    for _ in $(seq 1 20); do
        sleep 0.5
        ip netns exec wfs-client ping -c1 -W1 10.0.0.1 >/dev/null 2>&1 && break
    done
    sleep 3   # let the second path validate before measuring
    ip netns exec wfs-client ip route replace 10.0.5.0/24 dev mqvpn0 2>/dev/null
    ip netns exec wfs-server python3 "$PAGELOAD" server --bind 0.0.0.0 --port 8080 &
    APP_PID=$!
    ip netns exec wfs-server iperf3 -s -B 10.0.0.1 >/dev/null 2>&1 &
    IPERF_PID=$!
    sleep 0.5
}

counters() {   # prints: rx_a rx_b tx_a tx_b
    ip netns exec wfs-client sh -c '
      for i in wfs-a0 wfs-b0; do printf "%s " $(cat /sys/class/net/$i/statistics/rx_bytes); done
      for i in wfs-a0 wfs-b0; do printf "%s " $(cat /sys/class/net/$i/statistics/tx_bytes); done'
}

record() {   # scenario config workload before after result
    python3 - "$@" >> "$CSV" <<'EOF'
import sys
sc, cf, wl, b, a, res = sys.argv[1:7]
b = list(map(int, b.split())); a = list(map(int, a.split()))
d = [y - x for x, y in zip(b, a)]
dn = d[0] + d[1] or 1; up = d[2] + d[3] or 1
print(f"{sc},{cf},{wl},{d[0]},{d[1]},{d[0]/dn:.3f},{d[2]},{d[3]},{d[2]/up:.3f},{res}")
EOF
}

jget() { python3 -c "import json,sys;print(json.load(sys.stdin)['$1'])" 2>/dev/null || echo ERR; }

fetch_page() {
    ip netns exec wfs-client python3 "$PAGELOAD" client --server "$APP_IP" \
        --port 8080 --spec "$1" --parallel 6 2>&1 | tail -1
}

run_page_loads() {   # one CSV row per page load: the per-page split is what a WF observer gets
    local scn="$1" label="$2" b a r
    for i in $(seq 1 "$REPS"); do
        b=$(counters); r=$(fetch_page "$PAGE_SPEC"); a=$(counters)
        record "$scn" "$label" "page$i" "$b" "$a" "s:$(echo "$r" | jget seconds)"
        sleep 1.5   # idle gap (= a new "page" for BWR's idle redraw)
    done
}

setup_netns
first=1
for sc in "${SCENARIOS[@]}"; do
    IFS=: read -r scn ra rb <<< "$sc"
    apply_tc "$ra" "$rb"
    for cfg in "${CONFIGS[@]}"; do
        IFS='|' read -r label sched envs extras <<< "$cfg"
        tag="${scn}_${label}"
        echo "=== $scn ($ra/$rb)  $label ==="
        start_vpn "$sched" "$envs" "$tag" "$extras"

        if [ "$first" = 1 ]; then   # one captured page load per config
            ip netns exec wfs-client tcpdump -i wfs-a0 -s 96 -w "$OUT/pcap_${tag}_A.pcap" udp port 4433 2>/dev/null &
            T1=$!
            ip netns exec wfs-client tcpdump -i wfs-b0 -s 96 -w "$OUT/pcap_${tag}_B.pcap" udp port 4433 2>/dev/null &
            T2=$!
            sleep 1
            fetch_page "$PAGE_SPEC" >/dev/null
            sleep 1; kill "$T1" "$T2" 2>/dev/null; wait "$T1" "$T2" 2>/dev/null
            python3 "$PCAPSPLIT" --client-ip 192.168.10.1,192.168.20.1 --port 4433 \
                --out "$OUT/trace_${tag}.csv" "$OUT/pcap_${tag}_A.pcap" "$OUT/pcap_${tag}_B.pcap" \
                > "$OUT/trace_${tag}_summary.json"
            sleep 1.5
        fi

        run_page_loads "$scn" "$label"

        b=$(counters); r=$(fetch_page 20000000); a=$(counters)
        record "$scn" "$label" bulk "$b" "$a" "mbps:$(echo "$r" | jget mbps)"
        sleep 1

        b=$(counters)
        r=$(ip netns exec wfs-client iperf3 -c 10.0.0.1 -u -R -b 20M -t 5 -l 1200 -J 2>/dev/null \
              | python3 -c 'import json,sys;d=json.load(sys.stdin)["end"]["sum"];print("mbps:%.1f;loss:%.1f%%" % (d["bits_per_second"]/1e6, d["lost_percent"]))' 2>/dev/null || echo ERR)
        a=$(counters)
        record "$scn" "$label" udp "$b" "$a" "$r"

        stop_vpn
    done
    first=0
done

echo; column -s, -t < "$CSV"
