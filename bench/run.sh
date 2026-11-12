#!/bin/sh
# bon's swarm benchmark: a throwaway sandbox, stub agents, one `bon code` (code,
# foil and counterexample searches) and one `bon counterexample` on the trunk
# it pushes, measured as a whole process tree. See bench/README.md.
#
#   sh bench/run.sh WIDTH [TAG]
#
# Settings, by environment (defaults in brackets):
#   BENCH          where sandboxes and results go [$TMPDIR/bon-bench]
#   BON            the bon binary [target/debug/bon, built first]
#   CX_WIDTH       counterexample and foil searches' width [4]
#   SLEEP          seconds each stub waits, modelling the model [30]
#   K              times each stub runs the checks itself [1]
#   VARIANTS       distinct code edits; the rest are byte-identical [4]
#   TEST_VARIANTS  distinct counterexample tests [2]
#   TIME           each agent process's time limit, seconds [1800]
# and bon's own pool knobs, passed through: BON_GENERATION, BON_CHECKS,
# BON_CHECK_THREADS, BON_CORES, BON_MEMORY_GB.
set -eu
WIDTH=${1:?usage: run.sh WIDTH [TAG]}
TAG=${2:-w$WIDTH}
REPO=$(cd "$(dirname "$0")/.." && pwd)
BENCH=${BENCH:-${TMPDIR:-/tmp}/bon-bench}
CX_WIDTH=${CX_WIDTH:-4}
SLEEP=${SLEEP:-30}
K=${K:-1}
VARIANTS=${VARIANTS:-4}
TEST_VARIANTS=${TEST_VARIANTS:-2}
TIME=${TIME:-1800}
if [ -z "${BON:-}" ]; then
  (cd "$REPO" && cargo build -q --offline)
  BON=$REPO/target/debug/bon
fi
mkdir -p "$BENCH"
BENCH=$(cd "$BENCH" && pwd -P)
SANDBOX=$BENCH/sandbox-$TAG
rm -rf "$SANDBOX"
mkdir -p "$SANDBOX"
ORIGIN=$SANDBOX/origin.git
WORK=$SANDBOX/kernel
git init -q --bare -b main "$ORIGIN"
cp -R "$REPO/bench/sandbox" "$WORK"
mkdir -p "$WORK/.bon"
cp "$REPO/bench/stub.sh" "$WORK/.bon/stub.sh"
printf 'SLEEP=%s\nK=%s\nVARIANTS=%s\nTEST_VARIANTS=%s\n' "$SLEEP" "$K" "$VARIANTS" "$TEST_VARIANTS" > "$WORK/.bon/stub.env"
printf '/target\n/.bon/traces/\n' > "$WORK/.gitignore"
printf 'id\tintent\n' > "$WORK/.bon/queue.tsv"
cat > "$WORK/.bon/bon.toml" <<EOF
# The benchmark's sandbox: stub agents, a local bare origin, no traces remote.
limit = 1000.0
rate = 0

[agent_process]
limit = 1.0
time = $TIME

[checks]
paths = ["src/spec.rs", "tests/trunk.rs", "examples/kernel.rs"]
test = ["cargo test -q"]
verify = ["cargo verus verify"]
agree = ["cargo run -q --example kernel"]
rank = { code = "echo 0" }

[[harness]]
name = "stub"
model = "stub"
command = ["/bin/sh", ".bon/stub.sh"]
n = [$WIDTH]

[counterexample]
harness = [{ name = "stub", model = "stub", command = ["/bin/sh", ".bon/stub.sh"], n = [$CX_WIDTH] }]
path = "tests/counterexample.rs"
build = "cargo test -q --no-run --test counterexample"
run = "cargo test -q --test counterexample"
tests = ["tests/"]
visible = ["Cargo.toml", "Cargo.lock"]
EOF
# The lockfile, offline, from whatever cargo home this shell has.
(cd "$WORK" && cp "$REPO/Cargo.lock" . && cargo generate-lockfile --offline -q)
(cd "$WORK" && git init -q -b main && git add -A \
  && git -c user.name=bench -c user.email=bench@localhost commit -q -m "a kernel whose max Verus rejects" \
  && git remote add origin "$ORIGIN" && git push -q origin main)

# Safety: bon pushes, so origin must be the local bare repository and nothing
# may name a traces remote.
remotes=$(cd "$WORK" && git remote -v)
echo "$remotes"
if [ "$(echo "$remotes" | awk '{print $2}' | sort -u)" != "$ORIGIN" ]; then echo "refusing: a remote other than $ORIGIN" >&2; exit 1; fi
if grep -q '^traces' "$WORK/.bon/bon.toml"; then echo "refusing: bon.toml names a traces remote" >&2; exit 1; fi

OUT=$BENCH/results-$TAG
mkdir -p "$OUT"
run() {
  name=$1; shift
  (cd "$WORK" && BON_CLEANUP=own python3 -I "$REPO/bench/measure.py" "$OUT/$name.json" -- "$BON" "$@" > "$OUT/$name.out" 2> "$OUT/$name.err") || true
  # Check runs the judge executed, and those its verdict cache answered.
  executed=$(grep -rl '^exit: ' "$WORK/.bon/traces" 2>/dev/null | grep -v '/harness$' | wc -l | tr -d ' ')
  cached=$(grep -rl '^cached: ' "$WORK/.bon/traces" 2>/dev/null | wc -l | tr -d ' ')
  python3 -I - "$OUT/$name.json" "$executed" "$cached" "$TAG" "$WIDTH" <<'PY'
import json, sys
p, executed, cached, tag, width = sys.argv[1:6]
r = json.load(open(p))
r.update(tag=tag, width=int(width), checks_executed=int(executed), checks_cached=int(cached))
json.dump(r, open(p, "w"))
print(json.dumps(r))
PY
  tail -3 "$OUT/$name.err"
}
# Each command's traces are moved aside after it, so each counts its own.
run code code
mv "$WORK/.bon/traces" "$OUT/traces-code"
run counterexample counterexample
mv "$WORK/.bon/traces" "$OUT/traces-counterexample"
echo "results: $OUT"
