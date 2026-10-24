#!/usr/bin/env bash
# Runs the latency benchmark under emulated network conditions. Rootless:
# everything lives in a private network namespace, netem shapes `lo`.
# Each packet crosses `lo` once, so the delay below is half the RTT.
#
# usage: nix/bench-netem.sh [ws|quic] [iterations] [profile...]
set -euo pipefail

transport=${1:-quic}
iterations=${2:-50}
shift $(($# < 2 ? $# : 2))

# No jitter: netem jitter reorders packets, which real links rarely do and
# which QUIC's loss detection punishes far more than TCP's.
declare -A profiles=(
  [lan]="delay 0.5ms"
  [dsl]="delay 12ms"
  [lte]="delay 30ms loss 1%"
  [bad]="delay 75ms loss 3% rate 1mbit"
)
selected=("$@")
[[ ${#selected[@]} -gt 0 ]] || selected=(lan dsl lte bad)

cargo build --release --quiet --example latency
bin=$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/release/examples/latency

for profile in "${selected[@]}"; do
  netem=${profiles[$profile]:?unknown profile $profile}
  echo "== $profile ($netem)"
  unshare -rn sh -c "
    ip link set lo up
    tc qdisc add dev lo root netem $netem
    exec '$bin' '$transport' '$iterations'
  "
done
