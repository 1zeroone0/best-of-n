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
#   PROJECT        kernel (bench/sandbox's max) or bon (bon's own exec::eq)
#   BEHAVIORS      kernel: code edits also set pick, index % BEHAVIORS of them
#                  to b (trunk's is a; the spec allows both): verified
#                  candidates that behave differently [1]
#   CX_MODE        kernel: the tests counterexample stubs write [blind]
#                    blind  max only, as the spec says: they accept every
#                           correct max, whatever pick does
#                    split  pick 1 2 = 2 (variant 0 alone; the rest max too):
#                           they tell the behaviors apart
#                    few    blind, but only index 0's builds
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
# Its reply begins at once (a model's first token), then takes SLEEP: bon
# starts a search's other agent processes at its first one's first output.
echo "stub $kind $index: replying"
sleep "$SLEEP"
PROJECT=${PROJECT:-kernel}
v=$((index % VARIANTS))
if [ "$PROJECT" = bon ]; then
  # bon's own source: trunk's exec::eq is wrong; .bon/fix/ holds it right,
  # .bon/foil/ as trunk has it. Variant v > 0 is the fix with its own comment.
  case "$kind" in
    code)
      cp .bon/fix/src/exec.rs src/exec.rs
      if [ "$v" -gt 0 ]; then echo "// variant $v" >> src/exec.rs; fi
      ;;
    foil) cp .bon/foil/src/exec.rs src/exec.rs ;;
    counterexample)
      t=$((index % TEST_VARIANTS))
      mkdir -p tests
      {
        echo "// A blind test of exec::eq (variant $t)."
        echo "fn text(s: &str) -> Vec<char> { s.chars().collect() }"
        echo "#[test]"
        echo 'fn a_prefix_is_not_equal() { assert!(!best_of_n::exec::eq(&text("ab"), &text("abc"))); }'
        if [ "$t" -ne 0 ]; then
          echo "#[test]"
          echo "fn equal() { assert!(best_of_n::exec::eq(&text(\"$t\"), &text(\"$t\"))); }"
        fi
      } > tests/counterexample.rs
      ;;
  esac
else
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
    if [ $((index % ${BEHAVIORS:-1})) -eq 1 ]; then sed -i '' 's/^    a$/    b/' src/lib.rs; fi
    # Past four, a variant is the same fix with its own comment: its own tree.
    if [ "$v" -ge 4 ]; then echo "// variant $v" >> src/lib.rs; fi
    ;;
  foil)
    # Every foil is the same wrong reading: the tests miss it, Verus does not.
    sed -i '' "s/^    if .* else .*\$/$wrong/" src/lib.rs
    ;;
  counterexample)
    v=$((index % TEST_VARIANTS))
    mode=${CX_MODE:-blind}
    mkdir -p tests
    {
      echo "// A blind test of max (variant $v)."
      # split: variant 0 tests pick alone (the smallest test, so the one that
      # lands); the others max too, so they reject a foil once pick is settled.
      if [ "$mode" != split ] || [ "$v" -ne 0 ]; then
        echo "#[test]"
        echo "fn smaller_first() { assert_eq!(kernel::max(1, 2), 2); }"
      fi
      if [ "$v" -ne 0 ]; then
        echo "#[test]"
        echo "fn equal() { assert_eq!(kernel::max($v, $v), $v); }"
      fi
      if [ "$mode" = split ]; then
        echo "#[test]"
        echo "fn picks_the_second() { assert_eq!(kernel::pick(1, 2), 2); }"
      fi
      if [ "$mode" = few ] && [ "$index" -ne 0 ]; then echo "fn does_not_build() -> u64 { }"; fi
    } > tests/counterexample.rs
    ;;
esac
fi
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
