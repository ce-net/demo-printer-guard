#!/usr/bin/env bash
# Run the four attempts (direct, over-temperature, safe, replay) and write the report.
# Uses the stack from `cargo run -- up` if it is running; otherwise starts one and stops it after.
#   ./scripts/try-all.sh [report.json]      (default: proof/report.json)
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-proof/report.json}"
port="${PG_PORT:-7840}"

is_up() { (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; }

cargo build --release -q
pid=""
if ! is_up; then
  echo "starting the stack (cargo run -- up) for this run"
  set -m                                   # own process group, so one kill stops every child
  cargo run --release -q -- up > .up.log 2>&1 &
  pid=$!
  set +m
  trap 'kill -- -"$pid" 2>/dev/null || true' EXIT
  for _ in $(seq 1 300); do
    grep -q '^published:' .up.log 2>/dev/null && break
    kill -0 "$pid" 2>/dev/null || { cat .up.log; exit 1; }
    sleep 0.2
  done
fi
cargo run --release -q -- try-all --out "$out"
