// Code generated from src/gates.rs, src/wasm.rs, src/projection.rs by bon types. DO NOT EDIT.

package kernel

import "encoding/json"

// A git commit, by its hash. Its own type: a commit is never a path.
type Commit = string

// A path in a commit's tree.
type Path = string

// One line of the queue.
type Intent = string

// A WebVTT file.
type Transcript = Path

// A WebVTT cue, by its start time in milliseconds.
type Cue = uint64

// A hash of an agree check's output: an identity, not a quantity, so it is
// its own type. Programs read it as a decimal string.
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

// Everything bon shows, over the time range in `filter`.
type Projection struct {
	// Whether trunk's head has a .bon/bon.toml.
	Configured bool   `json:"configured"`
	Repo       Repo   `json:"repo"`
	Totals     Totals `json:"totals"`
	// Every bon process in range, newest first.
	Processes []BonProcess `json:"processes"`
	// The bon processes of one goal, together: a row of the traces.
	Groups []GoalTrace `json:"groups"`
	// What is wanted and not yet in the spec.
	Queue *[]QueueLine `json:"queue"`
	// Queue proposals waiting for engineer: patches bon queue wrote.
	Proposals []Proposal   `json:"proposals"`
	Filter    Filter       `json:"filter"`
	Bounds    Bounds       `json:"bounds"`
	Spec      *SpecOutline `json:"spec"`
	System    *SpecGraph   `json:"system"`
	Sbom      *SbomFile    `json:"sbom"`
}

// The repository and its trunk.
type Repo struct {
	Name       *string    `json:"name"`
	Head       *string    `json:"head"`
	Trunk      *string    `json:"trunk"`
	Remote     *string    `json:"remote"`
	RemoteHead *string    `json:"remote_head"`
	RemoteTime *int64     `json:"remote_time"`
	Subject    *string    `json:"subject"`
	LastPush   *LastPush  `json:"last_push"`
	SincePush  *SincePush `json:"since_push"`
	Pushed     *bool      `json:"pushed"`
	Now        int64      `json:"now"`
}

type LastPush struct {
	Commit *string `json:"commit"`
	Time   *int64  `json:"time"`
}

// Commits on trunk since bon last pushed, and who made them.
type SincePush struct {
	Commits uint64   `json:"commits"`
	Authors []string `json:"authors"`
}

// What everything in range cost, and what came of it.
type Totals struct {
	Cost                 float64  `json:"cost"`
	Generation           float64  `json:"generation"`
	TimeCost             float64  `json:"time_cost"`
	Pushed               float64  `json:"pushed"`
	NotPushed            float64  `json:"not_pushed"`
	InFlight             float64  `json:"in_flight"`
	Rate                 *float64 `json:"rate"`
	PerVerifiedCandidate *float64 `json:"per_verified_candidate"`
	PerPush              *float64 `json:"per_push"`
	Pushes               uint64   `json:"pushes"`
	Verified             uint64   `json:"verified"`
	Candidates           uint64   `json:"candidates"`
}

// Where a goal came from: the goal, the commit and its subject.
type About struct {
	Goal    string `json:"goal"`
	From    string `json:"from"`
	Subject string `json:"subject"`
}

// What a push cost, and the commit it pushed.
type Push struct {
	Commit         *string  `json:"commit"`
	Cost           *float64 `json:"cost"`
	ToSelection    *float64 `json:"to_selection"`
	Counterexample *float64 `json:"counterexample"`
	Searches       *uint64  `json:"searches"`
	Processes      *uint64  `json:"processes"`
}

// The bon processes of one goal: one row of the traces.
type GoalTrace struct {
	Kind       string       `json:"kind"`
	Title      string       `json:"title"`
	About      About        `json:"about"`
	Outcome    string       `json:"outcome"`
	Sentence   string       `json:"sentence"`
	Cost       float64      `json:"cost"`
	Generation float64      `json:"generation"`
	TimeCost   float64      `json:"time_cost"`
	Push       *Push        `json:"push"`
	Time       int64        `json:"time"`
	Running    bool         `json:"running"`
	Processes  []BonProcess `json:"processes"`
}

// One run of a bon command, by its pid.
type BonProcess struct {
	Pid        uint64   `json:"pid"`
	Running    bool     `json:"running"`
	Kind       string   `json:"kind"`
	Goal       string   `json:"goal"`
	Title      string   `json:"title"`
	About      About    `json:"about"`
	Outcome    string   `json:"outcome"`
	Sentence   string   `json:"sentence"`
	Cost       float64  `json:"cost"`
	Generation float64  `json:"generation"`
	TimeCost   float64  `json:"time_cost"`
	Push       *Push    `json:"push"`
	Limit      *float64 `json:"limit"`
	Time       int64    `json:"time"`
	// Each line of its transitions file.
	Transitions []string      `json:"transitions"`
	Searches    []SearchTrace `json:"searches"`
}

// One search of a bon process, as its trace recorded it.
type SearchTrace struct {
	Search           uint64  `json:"search"`
	Kind             string  `json:"kind"`
	Goal             string  `json:"goal"`
	Params           Params  `json:"params"`
	Width            uint64  `json:"width"`
	Started          *int64  `json:"started"`
	Returned         uint64  `json:"returned"`
	Accepted         uint64  `json:"accepted"`
	Verified         uint64  `json:"verified"`
	Selected         *uint64 `json:"selected"`
	RecordedSelected *uint64 `json:"recorded_selected"`
	// derived (the kernel read its words), unreadable, or none.
	Kernel     string   `json:"kernel"`
	Blocked    *string  `json:"blocked"`
	Generation *float64 `json:"generation"`
	TimeCost   *float64 `json:"time_cost"`
	Cost       *float64 `json:"cost"`
	Rate       *float64 `json:"rate"`
	Seconds    *float64 `json:"seconds"`
	Time       *int64   `json:"time"`
	Running    bool     `json:"running"`
	Background bool     `json:"background"`
	Candidates []Facts  `json:"candidates"`
}

// What a search was granted with.
type Params struct {
	Goal      GoalRef  `json:"goal"`
	Base      string   `json:"base"`
	N         *uint64  `json:"n"`
	Limit     *float64 `json:"limit"`
	Authority string   `json:"authority"`
}

// A search's goal: a trunk commit, a selected candidate, or a transcript.
type GoalRef struct {
	Trunk      *string `json:"trunk"`
	Candidate  *string `json:"candidate"`
	Transcript *string `json:"transcript"`
}

// One agent process, from its facts.json.
type Facts struct {
	Index      uint64   `json:"index"`
	Harness    *string  `json:"harness"`
	Model      *string  `json:"model"`
	Generation *float64 `json:"generation"`
	Commit     *string  `json:"commit"`
	Accepted   bool     `json:"accepted"`
	Verified   bool     `json:"verified"`
	Rank       *int64   `json:"rank"`
	Diff       *uint64  `json:"diff"`
	Added      *uint64  `json:"added"`
	Removed    *uint64  `json:"removed"`
	// killed, over limit, price mismatch.
	Flags   []string `json:"flags"`
	Logs    []string `json:"logs"`
	Changed []string `json:"changed"`
	// A hash of each agree check's output: candidates with the same agree.
	Out []uint64 `json:"out"`
}

// A queue proposal: a patch adding intents, each with the cue it came from.
type Proposal struct {
	Name    string           `json:"name"`
	Path    string           `json:"path"`
	Source  string           `json:"source"`
	Intents []ProposedIntent `json:"intents"`
	// Cues only one candidate cited, shown apart from the proposal.
	Contested []string `json:"contested"`
}

type ProposedIntent struct {
	Id     *uint64 `json:"id"`
	Intent string  `json:"intent"`
	Cue    *string `json:"cue"`
}

// One line of the queue.
type QueueLine struct {
	Id     uint64 `json:"id"`
	Intent string `json:"intent"`
}

// The time range bon was asked for.
type Filter struct {
	Since *int64  `json:"since"`
	Until *int64  `json:"until"`
	Find  *string `json:"find"`
}

// The earliest and latest bon process on record.
type Bounds struct {
	Earliest *int64 `json:"earliest"`
	Latest   *int64 `json:"latest"`
}

// The spec module as written: its state fields and its items.
type SpecOutline struct {
	Path   string      `json:"path"`
	Fields []SpecField `json:"fields"`
	Items  []SpecItem  `json:"items"`
}

// A field of the spec's state machine.
type SpecField struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Sharding *string `json:"sharding"`
	Doc      *string `json:"doc"`
}

// A type, predicate, transition, property or invariant of the spec, with its `///` line.
type SpecItem struct {
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Doc      *string  `json:"doc"`
	Reads    []string `json:"reads"`
	Updates  []string `json:"updates"`
	Requires []string `json:"requires"`
}

// The spec and how it reaches the code: items, and what each ensures, implements and calls.
type SpecGraph struct {
	Nodes []SpecNode `json:"nodes"`
	// from, to, and how: ensures, implements, calls, transition, types.
	Edges   []Tuple3[string, string, string] `json:"edges"`
	Trusted []TrustedFunction                `json:"trusted"`
	Counts  Counts                           `json:"counts"`
}

// One item of the spec or of the code that reaches it.
type SpecNode struct {
	Id    string  `json:"id"`
	Layer string  `json:"layer"`
	Group string  `json:"group"`
	Name  string  `json:"name"`
	File  string  `json:"file"`
	Line  *uint64 `json:"line"`
	End   *uint64 `json:"end"`
	Doc   *string `json:"doc"`
	// Differs from trunk.
	Changed bool     `json:"changed"`
	Guards  []string `json:"guards"`
	Adds    []string `json:"adds"`
	Removes []string `json:"removes"`
	Uses    []string `json:"uses"`
	Trusted []string `json:"trusted"`
	Proof   bool     `json:"proof"`
	// A gate's contract, each clause as written.
	Requires []string `json:"requires"`
	Ensures  []string `json:"ensures"`
}

// A function in trusted code the bon process calls.
type TrustedFunction struct {
	Name    string  `json:"name"`
	File    string  `json:"file"`
	Line    uint64  `json:"line"`
	Doc     *string `json:"doc"`
	Changed bool    `json:"changed"`
}

type Counts struct {
	Predicates uint64 `json:"predicates"`
	Private    uint64 `json:"private"`
	Trusted    uint64 `json:"trusted"`
}

// .bon/sbom.json, and whether it is trunk's or the working tree's.
type SbomFile struct {
	Source   string `json:"source"`
	Document Sbom   `json:"document"`
}

// A CycloneDX SBOM: its components, services and properties.
type Sbom struct {
	Metadata   SbomMetadata `json:"metadata"`
	Components []Component  `json:"components"`
	Services   []Service    `json:"services"`
}

type SbomMetadata struct {
	Properties []Property `json:"properties"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// A library, tool or host component.
type Component struct {
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Version string          `json:"version"`
	Group   *string         `json:"group"`
	Purl    *string         `json:"purl"`
	Hashes  []ComponentHash `json:"hashes"`
}

type ComponentHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// A network service a harness calls.
type Service struct {
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
	Group     *string  `json:"group"`
}

// Tuple2 is written in JSON as a 2-element array.
type Tuple2[T0, T1 any] struct {
	F0 T0
	F1 T1
}

func (t *Tuple2[T0, T1]) UnmarshalJSON(b []byte) error {
	var raw [2]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &t.F0); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[1], &t.F1); err != nil {
		return err
	}
	return nil
}

func (t Tuple2[T0, T1]) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]any{t.F0, t.F1})
}

// Tuple3 is written in JSON as a 3-element array.
type Tuple3[T0, T1, T2 any] struct {
	F0 T0
	F1 T1
	F2 T2
}

func (t *Tuple3[T0, T1, T2]) UnmarshalJSON(b []byte) error {
	var raw [3]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &t.F0); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[1], &t.F1); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[2], &t.F2); err != nil {
		return err
	}
	return nil
}

func (t Tuple3[T0, T1, T2]) MarshalJSON() ([]byte, error) {
	return json.Marshal([3]any{t.F0, t.F1, t.F2})
}
