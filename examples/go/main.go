// A program built on the kernel's emitted types (kernel/kernel.go, written by
// bon types): it reads searches as the kernel emits them, one JSON object per
// line, and prints what each holds. It decides nothing; the kernel does.
//
//	cargo run -q --example kernel | go run .
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"bon/examples/go/kernel"
)

// The search's kind and goal, in the spec's words.
func kind(k kernel.Kind) string {
	switch {
	case k.Queue != nil:
		return "queue " + k.Queue.Goal
	case k.Code != nil:
		return "code " + k.Code.Goal
	case k.Compaction != nil:
		return "compaction " + k.Compaction.Goal
	case k.Counterexample != nil && k.Counterexample.Goal != nil:
		return fmt.Sprintf("counterexample on search %d candidate %d", k.Counterexample.Goal.Search, k.Counterexample.Goal.Index)
	case k.Counterexample != nil:
		return "counterexample on trunk"
	}
	return "unknown kind"
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	for in.Scan() {
		if !strings.HasPrefix(in.Text(), "{") {
			continue
		}
		var s kernel.Search
		if err := json.Unmarshal(in.Bytes(), &s); err != nil {
			fmt.Fprintln(os.Stderr, "not a search:", err)
			os.Exit(1)
		}
		returned, accepted := 0, 0
		for _, c := range s.Results {
			if c != nil {
				returned++
				if c.Accepted {
					accepted++
				}
			}
		}
		fmt.Printf("%s: %d of %d agent processes returned a candidate, %d accepted\n", kind(s.Kind), returned, s.N, accepted)
	}
}
