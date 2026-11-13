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
#   FEEDBACK       kernel: 1, the first attempt's code stubs write a fix a
#                  test rejects, and a stub that sees those verdicts in its
#                  prompt writes the right one (use ATTEMPTS=2) [0]
#   TIME           each agent process's time limit, seconds [1800]
#   CHECK_TIME     each check's cutoff, seconds [1800]
#   PROJECT        kernel: the small crate in bench/sandbox; bon: bon's own
#                  source at this commit, one function broken [kernel]
#   PROGRAM        what the code, compaction and queue searches' role runs, a
#                  host file role's keys [the stub]; e.g. a real one, through
#                  bon-sample: 'program = ["/path/bon-sample"], client = "claude",
#                  model = "claude-haiku-5-5", context = 80000'
#   CX_PROGRAM     what the counterexample and foil searches' role runs, likewise [the stub]
#   AGENT_PROCESSES, CHECK_PROCESSES, CHECK_THREADS
#                  the host file's pool sizes, to size the pools as another
#                  machine's [unset: this machine's defaults]
# bon reads a host file the run writes (BON_HOST): the installed host file's
# path, toolchain homes and prices, the two roles, a user layer of the run's
# own in the sandbox (its verdict cache and process list), and those sizes.
# Each check runs as its slot's user, check0, check1, …: there must be as
# many as the check pool (bon setup makes them).
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
FEEDBACK=${FEEDBACK:-0}
ATTEMPTS=${ATTEMPTS:-1}
NS=$WIDTH; i=1; while [ "$i" -lt "$ATTEMPTS" ]; do NS="$NS, $WIDTH"; i=$((i + 1)); done
TIME=${TIME:-1800}
CHECK_TIME=${CHECK_TIME:-1800}
PROJECT=${PROJECT:-kernel}
STUB='program = ["/bin/sh", ".bon/stub.sh"]'
PROGRAM=${PROGRAM:-$STUB}
CX_PROGRAM=${CX_PROGRAM:-$STUB}
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
    # bon's source at HEAD, its own .bon/ replaced by the benchmark's (its
    # account kept, which a test reads) and
    # bench/ (which says how trunk is broken) left out. On its trunk exec::eq
    # says a strict prefix equals the longer text: the tests miss it, Verus
    # does not. A code stub restores the file kept in .bon/fix/, which is
    # there only when stubs write the code: a real program would read the
    # answer in it.
    WORK=$SANDBOX/bon
    mkdir -p "$WORK"
    (cd "$REPO" && git archive HEAD) | tar -x -C "$WORK"
    rm -rf "$WORK/bench" && find "$WORK/.bon" -mindepth 1 -maxdepth 1 ! -name account.json ! -name sbom.json -exec rm -rf {} +
    if [ "$PROGRAM" = "$STUB" ]; then mkdir -p "$WORK/.bon/fix/src" && cp "$WORK/src/exec.rs" "$WORK/.bon/fix/src/exec.rs"; fi
    perl -0pi -e 's/    a\.len\(\) == b\.len\(\) && is_prefix_of\(a, b\)\n/    a.len() <= b.len() && is_prefix_of(a, b)\n/ or die "exec::eq not found\n"' "$WORK/src/exec.rs"
    PATHS='"src/spec.rs", "src/gates.rs", "examples/kernel.rs"'
    ;;
  *) echo "PROJECT is kernel or bon" >&2; exit 1 ;;
esac
cp "$REPO/bench/stub.sh" "$WORK/.bon/stub.sh"
printf 'PROJECT=%s\nSLEEP=%s\nK=%s\nVARIANTS=%s\nTEST_VARIANTS=%s\nBEHAVIORS=%s\nCX_MODE=%s\nFEEDBACK=%s\n' "$PROJECT" "$SLEEP" "$K" "$VARIANTS" "$TEST_VARIANTS" "$BEHAVIORS" "$CX_MODE" "$FEEDBACK" > "$WORK/.bon/stub.env"
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
paths = [$PATHS]
test = ["cargo test -q"]
verify = ["cargo verus verify"]
agree = ["cargo run -q --example kernel"]
rank = { code = "echo 0" }
time = $CHECK_TIME

[searches]
code = { role = "code", n = [$NS] }
compaction = { role = "code", n = [$NS] }
queue = { role = "code", n = [$NS] }
counterexample = { role = "test", n = [$CX_WIDTH] }
foil = { role = "test", n = [$CX_WIDTH] }

[counterexample]
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

# The run's host file, written here: the installed host file's PATH,
# toolchain homes and prices (keys of the same shape in every host file
# bon has read), this run's two roles, its own user layer (so its own verdict
# cache and process list), and any pool sizes asked for.
HOSTFILE=$SANDBOX/host.toml
HOST=${HOST:-/etc/bon/host.toml}
{
  grep -E '^(path|rustup_home|cargo_home) *=' "$HOST"
  echo "user = \"$SANDBOX/user\""
  for k in agent_processes check_processes check_threads; do
    v=$(eval "echo \${$(echo $k | tr a-z A-Z):-}")
    if [ -n "$v" ]; then echo "$k = $v"; fi
  done
  # A role's keys, one per line: `program = [...], client = "x"` splits at `, client =`.
  keys() { echo "$1" | perl -pe 's/, ([a-z_]+ =)/\n$1/g'; }
  printf '\n[roles.code]\n%s\n\n[roles.test]\n%s\n\n' "$(keys "$PROGRAM")" "$(keys "$CX_PROGRAM")"
  # [prices], the last table of the host file bon setup writes.
  sed -n '/^\[prices\]/,$p' "$HOST"
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
