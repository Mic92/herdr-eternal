#!/usr/bin/env bash
# Runs the latency benchmark under emulated network conditions. Rootless:
# everything lives in a private network namespace, netem shapes `lo`.
# Each packet crosses `lo` once, so the delay below is half the RTT.
#
# usage: nix/bench-netem.sh [ws|quic|ssh] [iterations] [profile...]
#
# `ssh` runs a private, unprivileged sshd in the namespace as a baseline.
set -euo pipefail

if [[ ${1:-} == --in-netns ]]; then
  ip link set lo up
  read -ra opts <<<"$2"
  tc qdisc add dev lo root netem "${opts[@]}"
  eval "$3"
  shift 3
  exec "$@"
fi

transport=${1:-quic}
iterations=${2:-50}
shift $(($# < 2 ? $# : 2))

# No jitter: netem jitter reorders packets, which real links rarely do and
# which QUIC's loss detection punishes far more than TCP's.
declare -A profiles=(
  [lan]="delay 0.5ms"
  [dsl]="delay 12ms"
  [lte]="delay 30ms loss 1%"
  [lossy]="delay 30ms loss 5%"
  [bad]="delay 75ms loss 3% rate 1mbit"
)
selected=("$@")
[[ ${#selected[@]} -gt 0 ]] || selected=(lan dsl lte lossy bad)

cargo build --release --quiet --example latency
bin=$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)/release/examples/latency

setup=
args=()
if [[ $transport == ssh ]]; then
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' EXIT
  ssh-keygen -q -t ed25519 -N "" -f "$dir/host"
  ssh-keygen -q -t ed25519 -N "" -f "$dir/user"
  cp "$dir/user.pub" "$dir/authorized_keys"
  cat >"$dir/sshd_config" <<EOF
ListenAddress 127.0.0.1:2222
HostKey $dir/host
AuthorizedKeysFile $dir/authorized_keys
PidFile none
StrictModes no
Compression yes
EOF
  # Non-root sshd only authenticates the invoking user, so keep our uid.
  setup="$(command -v sshd) -f $dir/sshd_config -E $dir/sshd.log; sleep 0.2"
  args=(ssh -C -F /dev/null -i "$dir/user" -p 2222 -o BatchMode=yes
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR 127.0.0.1)
fi

for profile in "${selected[@]}"; do
  netem=${profiles[$profile]:?unknown profile $profile}
  echo "== $profile ($netem)"
  unshare --map-current-user --keep-caps -n "$BASH" "$0" --in-netns "$netem" "$setup" \
    "$bin" "$transport" "$iterations" "${args[@]}"
done
