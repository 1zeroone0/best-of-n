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
#   BEHAVIORS      kernel: how many behaviors verified code stubs show [1]
#   CX_MODE        kernel: the counterexample stubs' tests: blind, split or few [blind]
#   ATTEMPTS       attempts `bon code` may make, each WIDTH wide [1]
#   TIME           each agent process's time limit, seconds [1800]
#   PROJECT        kernel: the small crate in bench/sandbox; bon: bon's own
#                  source at this commit, one function broken [kernel]
#   HARNESS        the code search's harness, a TOML inline table's fields
#                  without n [the stub]; e.g. a real one, through bon-sample:
#                  'name = "claude", model = "claude-haiku-5-5", command = [...]'
#   CX_HARNESS     the counterexample and foil searches' harness, likewise [the stub]
#   GENERATION, CHECKS, CHECK_THREADS, CORES, MEMORY_GB
#                  the host file's pool keys, to size the pools as another
#                  machine's [unset: /etc/bon/host.toml's, then this machine's]
# bon reads its own host file for the run (BON_HOST): /etc/bon/host.toml with
# the verdict cache in the sandbox, cleanup = "own", and those keys.
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
BEHAVIORS=${BEHAVIORS:-1}
CX_MODE=${CX_MODE:-blind}
ATTEMPTS=${ATTEMPTS:-1}
NS=$WIDTH; i=1; while [ "$i" -lt "$ATTEMPTS" ]; do NS="$NS, $WIDTH"; i=$((i + 1)); done
TIME=${TIME:-1800}
PROJECT=${PROJECT:-kernel}
STUB='name = "stub", model = "stub", command = ["/bin/sh", ".bon/stub.sh"]'
HARNESS=${HARNESS:-$STUB}
CX_HARNESS=${CX_HARNESS:-$STUB}
if [ -z "${BON:-}" ]; then
  (cd "$REPO" && cargo build -q --offline)
  BON=$REPO/target/debug/bon
fi
mkdir -p "$BENCH"
BENCH=$(cd "$BENCH" && pwd -P)
SANDBOX=$BENCH/sandbox-$TAG
rm -rf "$SANDBOX"
mkdir -p "$SANDBOX"
# The repository is engineer's alone: bon's isolation gate refuses to run if
# agent can reach it (as it could if $BENCH's ancestors let agent through).
chmod 0700 "$SANDBOX"
ORIGIN=$SANDBOX/origin.git
git init -q --bare -b main "$ORIGIN"
case "$PROJECT" in
  kernel)
    WORK=$SANDBOX/kernel
    cp -R "$REPO/bench/sandbox" "$WORK"
    mkdir -p "$WORK/.bon"
    PATHS='"src/spec.rs", "tests/trunk.rs", "examples/kernel.rs"'
    ;;
  bon)
    # bon's source at HEAD, its own .bon/ replaced by the benchmark's. On its
    # trunk exec::eq says a strict prefix equals the longer text: the tests
    # miss it, Verus does not. The stub restores the file kept in .bon/fix/.
    WORK=$SANDBOX/bon
    mkdir -p "$WORK"
    (cd "$REPO" && git archive HEAD) | tar -x -C "$WORK"
    rm -rf "$WORK/.bon" && mkdir -p "$WORK/.bon/fix/src" "$WORK/.bon/foil/src"
    cp "$WORK/src/exec.rs" "$WORK/.bon/fix/src/exec.rs"
    perl -0pi -e 's/    a\.len\(\) == b\.len\(\) && is_prefix_of\(a, b\)\n/    a.len() <= b.len() && is_prefix_of(a, b)\n/ or die "exec::eq not found\n"' "$WORK/src/exec.rs"
    cp "$WORK/src/exec.rs" "$WORK/.bon/foil/src/exec.rs"
    PATHS='"src/spec.rs", "src/gates.rs", "examples/kernel.rs"'
    ;;
  *) echo "PROJECT is kernel or bon" >&2; exit 1 ;;
esac
cp "$REPO/bench/stub.sh" "$WORK/.bon/stub.sh"
printf 'PROJECT=%s\nSLEEP=%s\nK=%s\nVARIANTS=%s\nTEST_VARIANTS=%s\nBEHAVIORS=%s\nCX_MODE=%s\n' "$PROJECT" "$SLEEP" "$K" "$VARIANTS" "$TEST_VARIANTS" "$BEHAVIORS" "$CX_MODE" > "$WORK/.bon/stub.env"
printf '/target\n/.bon/traces/\n' > "$WORK/.gitignore"
printf 'id\tintent\n' > "$WORK/.bon/queue.tsv"
cat > "$WORK/.bon/bon.toml" <<EOF
# The benchmark's sandbox: stub agents, a local bare origin, no traces remote.
limit = 1000.0
rate = 0
harness = [{ $HARNESS, n = [$NS] }]

[agent_process]
limit = 1.0
time = $TIME

[checks]
paths = [$PATHS]
test = ["cargo test -q"]
verify = ["cargo verus verify"]
agree = ["cargo run -q --example kernel"]
rank = { code = "echo 0" }

[counterexample]
harness = [{ $CX_HARNESS, n = [$CX_WIDTH] }]
path = "tests/counterexample.rs"
build = "cargo test -q --no-run --test counterexample"
run = "cargo test -q --test counterexample"
tests = ["tests/"]
visible = ["Cargo.toml", "Cargo.lock"]
EOF
# The kernel's lockfile, offline, from whatever cargo home this shell has (bon's is its own).
if [ "$PROJECT" = kernel ]; then (cd "$WORK" && cp "$REPO/Cargo.lock" . && cargo generate-lockfile --offline -q); fi
(cd "$WORK" && git init -q -b main && git add -A \
  && git -c user.name=bench -c user.email=bench@localhost commit -q -m "a kernel whose max Verus rejects" \
  && git remote add origin "$ORIGIN" && git push -q origin main)

# Safety: bon pushes, so origin must be the local bare repository and nothing
# may name a traces remote.
remotes=$(cd "$WORK" && git remote -v)
echo "$remotes"
if [ "$(echo "$remotes" | awk '{print $2}' | sort -u)" != "$ORIGIN" ]; then echo "refusing: a remote other than $ORIGIN" >&2; exit 1; fi
if grep -q '^traces' "$WORK/.bon/bon.toml"; then echo "refusing: bon.toml names a traces remote" >&2; exit 1; fi

# The run's host file: the host's, with this run's verdict cache, cleanup of
# its own directories only, and any pool sizing asked for. Top-level keys go
# before the first table; a key the host's file sets is replaced.
HOSTFILE=$SANDBOX/host.toml
keys="verdicts = \"$SANDBOX/verdicts\"
cleanup = \"own\""
for k in generation checks check_threads cores memory_gb; do
  v=$(eval "echo \${$(echo $k | tr a-z A-Z):-}")
  if [ -n "$v" ]; then keys="$keys
$k = $v"; fi
done
names=$(echo "$keys" | awk '{print $1}' | paste -s -d '|' -)
HOST=/etc/bon/host.toml
first=$(grep -n '^\[' "$HOST" | head -1 | cut -d: -f1)
first=${first:-$(($(wc -l < "$HOST") + 1))}
{
  head -n $((first - 1)) "$HOST" | grep -v -E "^($names)[ =]"
  printf '%s\n\n' "$keys"
  tail -n +"$first" "$HOST"
} > "$HOSTFILE"
chmod 0644 "$HOSTFILE"
export BON_HOST=$HOSTFILE

OUT=$BENCH/results-$TAG
mkdir -p "$OUT"
run() {
  name=$1; shift
  # The isolation gate has failed here for reasons outside bon (another
  # session on the host); it fails before anything runs, so try again.
  for try in 1 2 3; do
    (cd "$WORK" && python3 -I "$REPO/bench/measure.py" "$OUT/$name.json" -- "$BON" "$@" > "$OUT/$name.out" 2> "$OUT/$name.err") || true
    grep -q 'agent is not isolated' "$OUT/$name.err" || break
    echo "isolation gate failed; again in 30s" >&2; sleep 30
  done
  # Check runs the judge executed (a log that starts "exit:"), and those its
  # verdict cache answered ("cached:"); agent processes' own runs are not counted.
  python3 -I - "$OUT/$name.json" "$(python3 -I "$REPO/bench/count.py" "$WORK/.bon/traces")" "$TAG" "$WIDTH" <<'PY'
import json, sys
p, counts, tag, width = sys.argv[1:5]
r = json.load(open(p))
r.update(json.loads(counts), tag=tag, width=int(width))
json.dump(r, open(p, "w"))
print(json.dumps(r))
PY
  tail -3 "$OUT/$name.err"
}
# Each command's traces are moved aside after it, so each counts its own.
run code code
mv "$WORK/.bon/traces" "$OUT/traces-code" 2>/dev/null || true
run counterexample counterexample
mv "$WORK/.bon/traces" "$OUT/traces-counterexample" 2>/dev/null || true
echo "results: $OUT"
