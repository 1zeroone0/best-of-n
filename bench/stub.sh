#!/bin/sh
# A stub agent process: bon runs it as agent in the working directory, the
# prompt on stdin, in place of claude or codex. It behaves like a real agent,
# cheaply: it waits (the model), makes a small fixed edit by the prompt's kind,
# and runs the checks itself K times (an agent iterating).
#
# Its settings are .bon/stub.env, committed beside it on the sandbox's trunk:
#   SLEEP          seconds to wait, modelling the model
#   K              how many times it runs the tests and Verus itself
#   VARIANTS       code edits: index % VARIANTS picks one, so stubs whose
#                  indices agree modulo VARIANTS write byte-identical trees
#   TEST_VARIANTS  counterexample tests, likewise
set -u
. ./.bon/stub.env
prompt=$(cat)
# The working directory is /tmp/bon/<pid>.<search>.<index>/<repository>.
owner=$(basename "$(dirname "$PWD")")
index=${owner##*.}
case "$prompt" in
  *"does something the spec forbids"*) kind=foil ;;
  *"Trunk's checks reject this code"*) kind=code ;;
  *"Write one test, at"*) kind=counterexample ;;
  *) kind=other ;;
esac
sleep "$SLEEP"
wrong='    if a > b { a } else { a }'
case "$kind" in
  code)
    case $((index % VARIANTS)) in
      0) fix='    if a > b { a } else { b }' ;;
      1) fix='    if a >= b { a } else { b }' ;;
      2) fix='    if b > a { b } else { a }' ;;
      *) fix='    if a < b { b } else { a }' ;;
    esac
    sed -i '' "s/^    if a > b { a } else { a }\$/$fix/" src/lib.rs
    # Past four, a variant is the same fix with its own comment: its own tree.
    v=$((index % VARIANTS))
    if [ "$v" -ge 4 ]; then echo "// variant $v" >> src/lib.rs; fi
    ;;
  foil)
    # Every foil is the same wrong reading: the tests miss it, Verus does not.
    sed -i '' "s/^    if .* else .*\$/$wrong/" src/lib.rs
    ;;
  counterexample)
    v=$((index % TEST_VARIANTS))
    mkdir -p tests
    {
      echo "// A blind test of max (variant $v)."
      echo "#[test]"
      echo "fn smaller_first() { assert_eq!(kernel::max(1, 2), 2); }"
      if [ "$v" -ne 0 ]; then
        echo "#[test]"
        echo "fn equal() { assert_eq!(kernel::max($v, $v), $v); }"
      fi
    } > tests/counterexample.rs
    ;;
esac
# The agent iterating: its own runs of the checks, timed (a check slot's wait
# included), so a benchmark can say where a session's time went.
now() { /usr/bin/perl -MTime::HiRes=time -e 'printf "%.2f", time'; }
t0=$(now)
if [ "$kind" = code ] || [ "$kind" = foil ]; then
  i=0
  while [ "$i" -lt "$K" ]; do
    cargo test -q >/dev/null 2>&1
    cargo verus verify >/dev/null 2>&1
    i=$((i + 1))
  done
fi
t1=$(now)
echo "stub $kind $index: changed what the prompt asked"
/usr/bin/perl -e 'printf "stub-seconds: sleep %s own-checks %.2f\n", @ARGV' "$SLEEP" "$(/usr/bin/perl -e 'print $ARGV[1] - $ARGV[0]' "$t0" "$t1")"
