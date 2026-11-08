// Code generated from src/gates.rs, src/wasm.rs by bon types. DO NOT EDIT.

package kernel

import "encoding/json"

// A git commit, by its hash.
type Commit = string

// A path in a commit's tree.
type Path = string

// One line of the queue.
type Intent = string

// A WebVTT file.
type Transcript = Path

// A WebVTT cue, by its start time in milliseconds.
type Cue = uint64

// A hash of an agree check's output. Programs read it as a decimal string,
// since a JSON number loses u64 precision in a browser.
type Hash = string

// A process running as agent that writes one candidate.
type AgentProcess struct {
	Search uint64 `json:"search"`
	Index  uint64 `json:"index"`
}

// What a search is for: its kind, carrying its goal.
// One of its variants is set.
type Kind struct {
	Queue          *KindQueue          `json:"queue,omitempty"`
	Code           *KindCode           `json:"code,omitempty"`
	Compaction     *KindCompaction     `json:"compaction,omitempty"`
	Counterexample *KindCounterexample `json:"counterexample,omitempty"`
}

type KindQueue struct {
	Goal Transcript `json:"goal"`
}

type KindCode struct {
	Goal Commit `json:"goal"`
}

type KindCompaction struct {
	Goal Commit `json:"goal"`
	Out  []Hash `json:"out"`
}

type KindCounterexample struct {
	Goal *AgentProcess `json:"goal"`
}

// One generated change, as trusted code observed it.
type Candidate struct {
	Commit   Commit `json:"commit"`
	Base     Commit `json:"base"`
	Accepted bool   `json:"accepted"`
	Proved   bool   `json:"proved"`
	Changed  []Path `json:"changed"`
	Out      []Hash `json:"out"`
	// Each new intent, by the cue it cites. A repeated cue: the first counts.
	Intents []Tuple2[Cue, Intent] `json:"intents"`
	// Whether this candidate's test accepts each tested commit: the goal
	// search's candidates by index, and trunk's head (or a compaction's goal)
	// as -1. A repeated index: the first counts.
	Accepts                []Tuple2[int64, bool] `json:"accepts"`
	RejectsCounterexamples bool                  `json:"rejects_counterexamples"`
	Rank                   int64                 `json:"rank"`
	Diff                   uint64                `json:"diff"`
}

// One search, once every agent process has returned: `results[i]` is what
// agent process i returned.
type Search struct {
	Kind Kind   `json:"kind"`
	Base Commit `json:"base"`
	N    uint64 `json:"n"`
	// The check paths the manifest declares; the authority derives from them.
	Checks []Path `json:"checks"`
	// The paths holding the counterexamples' tests.
	Tests []Path `json:"tests"`
	// The trusted code the manifest's SBOM declares; no search may change it.
	Trusted []Path       `json:"trusted"`
	Limit   uint64       `json:"limit"`
	Results []*Candidate `json:"results"`
}

// A gate's answer when it names no candidate.
const NONE = -1

// A gate's answer when the words are not a search (or name no such agent process).
const NOT_A_SEARCH = -2

// Tuple2 is a pair, written in JSON as a two-element array.
type Tuple2[A, B any] struct {
	First  A
	Second B
}

func (t *Tuple2[A, B]) UnmarshalJSON(b []byte) error {
	var raw [2]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &t.First); err != nil {
		return err
	}
	return json.Unmarshal(raw[1], &t.Second)
}

func (t Tuple2[A, B]) MarshalJSON() ([]byte, error) { return json.Marshal([2]any{t.First, t.Second}) }
