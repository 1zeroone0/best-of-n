// Code generated from src/gates.rs, src/projection.rs by bon types. DO NOT EDIT.

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
	Foil           *KindFoil           `json:"foil,omitempty"`
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

type KindFoil struct {
	Goal    AgentProcess `json:"goal"`
	Changed []Path       `json:"changed"`
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
	Accepts []Tuple2[int64, bool] `json:"accepts"`
	// Whether this candidate's test accepts each foil, by its index in the
	// foil search. A repeated index: the first counts.
	AcceptsFoils           []Tuple2[int64, bool] `json:"accepts_foils"`
	RejectsCounterexamples bool                  `json:"rejects_counterexamples"`
	// Every agree check and the rank check exited 0.
	Measured bool `json:"measured"`
	// The paths the diff added, as git reports them.
	Added []Path `json:"added"`
	Rank  int64  `json:"rank"`
	Diff  uint64 `json:"diff"`
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
	// The trusted code the manifest's account declares; no search may change it.
	Trusted []Path       `json:"trusted"`
	Limit   uint64       `json:"limit"`
	Results []*Candidate `json:"results"`
}

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
	Proposals []Proposal `json:"proposals"`
	// What only engineer can answer, oldest first: pending, then resolved.
	Interrupts []Interrupt `json:"interrupts"`
	// Intents no longer on the queue, and the commit that took each off, newest first.
	Retired []Retired `json:"retired"`
	// What no search may change: bon's directory, the checks, trusted code.
	Protected []string     `json:"protected"`
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
	// Attempts by kind and width, by how each ended.
	Attempts []Attempts `json:"attempts"`
	// How bon processes ended, by kind.
	Ended []Ended `json:"ended"`
	// How many attempts of each kind each reason blocked.
	Reasons []Reason `json:"reasons"`
	// How many attempts of each kind exited, by when: during_a_search, or
	// after_its_searches (reported, before a transition), in older traces,
	// which hold no error; or the error the bon process recorded.
	Exits []Reason `json:"exits"`
	// Success probability by kind, and by attempt.
	Success []Success `json:"success"`
	// Cost per verified candidate by kind, program and model.
	PerVerified []PerVerified `json:"per_verified"`
	// The host's two semaphores against wall time.
	Utilization Utilization `json:"utilization"`
	// Time and cost to a push, by kind, and each search's as a fixed part
	// plus a part per distinct tree.
	RunTime []RunTime `json:"run_time"`
	// Interrupt turnaround, by kind.
	Turnaround []Turnaround `json:"turnaround"`
}

// One kind of interrupt's turnaround: of its interrupts, how many resolved
// and how many are pending, and the seconds from raised to resolved of those
// that resolved, as median and 90th percentile.
type Turnaround struct {
	Kind     string `json:"kind"`
	Resolved uint64 `json:"resolved"`
	Pending  uint64 `json:"pending"`
	Time     Spread `json:"time"`
}

// Every record a bon process writes, in one shape: what ran (program), what
// it was given (context), what it returned (output), how it was judged
// (verdict) and which behavior its output showed (behavior). An agent
// process: its program, its prompt, its candidate's commit, what its checks
// said (proved, accepted, rejected), its agree outputs' hashes. A check: its
// command, the tree it ran on, its output, its exit, its output's hash. A
// decision: engineer, what the interrupt showed, the commit that answered it,
// what came of it, the choice it showed.
type Record struct {
	Program  *string `json:"program"`
	Context  *string `json:"context"`
	Output   *string `json:"output"`
	Verdict  *string `json:"verdict"`
	Behavior *string `json:"behavior"`
}

// What only engineer can answer, derived from the traces and never stored:
// pending until the action that answers it, which bon recognises from what is
// already recorded; there is no dismiss. Kinds: `proposal` (a queue proposal
// awaiting acceptance), `blocked` (an attempt blocked with its width list or
// its limit spent), `transcript` (a transcript the host file routes nowhere).
type Interrupt struct {
	Kind string `json:"kind"`
	// The kind and what it is about: `blocked <trace>`, `proposal <source>`, `transcript <sha256>`.
	Id string `json:"id"`
	// The repository's name, and its root.
	Repository string `json:"repository"`
	Root       string `json:"root"`
	// What it is about: a goal's title, a proposal's source, a transcript.
	About string `json:"about"`
	// A block's reason, by the kernel's word; `limit` for a limit spent.
	Reason   *string `json:"reason"`
	Raised   int64   `json:"raised"`
	Resolved *int64  `json:"resolved"`
	// What happened, in a line or two, from the trace.
	What []string `json:"what"`
	// What engineer may do, and what each costs.
	Choices []Choice `json:"choices"`
	// The action that resolved it.
	Answer *Answer `json:"answer"`
	// What came of it: how the first bon process of its kind after it ended;
	// for a proposal it accepted, whether its intents are still queued.
	CameOfIt *string `json:"came_of_it"`
	// Its decision record, once bon has written it; its verdict is what came of it.
	Decision *Record `json:"decision"`
	// The transcript of the session that answered it, by path and SHA-256.
	Transcript *Transcript `json:"transcript"`
}

// One choice: its name, how it is made, and what it costs, from the traces.
type Choice struct {
	Choice string `json:"choice"`
	How    string `json:"how"`
	Cost   string `json:"cost"`
}

// The action that answered an interrupt: its commit, if it was one, and its
// subject, or a later attempt's trace; and which choice it showed.
type Answer struct {
	Commit  *string `json:"commit"`
	Subject string  `json:"subject"`
	Choice  string  `json:"choice"`
}

// A pointer to a transcript, and its hash.
type Transcript struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

// One kind's success probability, over every attempt (`attempt` none) or
// over each bon process's attempt-th attempt and the searches on it: per
// agent process, successes ÷ agent processes (successes: verified
// candidates; a foil search's foils), over reported searches; per attempt,
// pushed ÷ attempts that ended (pushed, blocked, landed).
type Success struct {
	Kind           string  `json:"kind"`
	Attempt        *uint64 `json:"attempt"`
	AgentProcesses uint64  `json:"agent_processes"`
	Successes      uint64  `json:"successes"`
	Ended          uint64  `json:"ended"`
	Pushed         uint64  `json:"pushed"`
}

// The agent processes of one kind, program and model that returned, how many
// were verified, their generation, and their share of their searches' time
// cost: cost per verified candidate is (generation + time_cost) ÷ verified.
type PerVerified struct {
	Kind           string  `json:"kind"`
	Program        string  `json:"program"`
	Model          string  `json:"model"`
	AgentProcesses uint64  `json:"agent_processes"`
	Verified       uint64  `json:"verified"`
	Generation     float64 `json:"generation"`
	TimeCost       float64 `json:"time_cost"`
}

// The host's agent_processes and check_processes semaphores over the reported
// searches in range: `wall` is the union of their wall times, in seconds.
type Utilization struct {
	Wall           float64 `json:"wall"`
	Searches       uint64  `json:"searches"`
	AgentProcesses Pool    `json:"agent_processes"`
	CheckProcesses Pool    `json:"check_processes"`
}

// One semaphore: the slot-seconds held, and its size where every search
// recorded the same one. Utilization is held ÷ (size × wall).
type Pool struct {
	Held float64 `json:"held"`
	Size *uint64 `json:"size"`
}

// One kind's run-time distribution: its pushes' time (seconds) and cost to a
// push, each as median and 90th percentile; and over `searches` of its
// reported searches, a search's seconds and cost as a fixed part plus a part
// per distinct tree, by least squares (inferred), none with too few.
type RunTime struct {
	Kind     string `json:"kind"`
	Pushes   uint64 `json:"pushes"`
	Time     Spread `json:"time"`
	Cost     Spread `json:"cost"`
	Searches uint64 `json:"searches"`
	Fit      *Fit   `json:"fit"`
}

// A median (the middle value, or the mean of the middle two) and a 90th
// percentile (the ⌈0.9 n⌉-th smallest); none of no values.
type Spread struct {
	Median *float64 `json:"median"`
	P90    *float64 `json:"p90"`
}

// Seconds and cost, each a fixed part plus a part per distinct tree.
type Fit struct {
	Time PerTree `json:"time"`
	Cost PerTree `json:"cost"`
}

// A fixed part, and a part per distinct tree.
type PerTree struct {
	Fixed   float64 `json:"fixed"`
	PerTree float64 `json:"per_tree"`
}

// Attempts of one kind at one width, by how each ended; `attempts` is their
// sum. An attempt is a code or compaction search with the foil and
// counterexample searches on its selection. Landed: a counterexample's test
// landed on trunk and the bon process went on. Exited: its bon process
// stopped during it, on the error it recorded or, in older traces, with no
// transition.
type Attempts struct {
	Kind     string `json:"kind"`
	Width    uint64 `json:"width"`
	Attempts uint64 `json:"attempts"`
	Pushed   uint64 `json:"pushed"`
	Blocked  uint64 `json:"blocked"`
	Landed   uint64 `json:"landed"`
	Exited   uint64 `json:"exited"`
	Running  uint64 `json:"running"`
}

// How the bon processes of one kind ended. Exited: stopped short of a final
// transition (killed, interrupted, an error), which is not a block. `expected`
// is the share of those that pushed or blocked (1-p)^k predicts would end
// blocked, p being this kind's success probability per attempt (pushed ÷
// attempts that ended) and k the attempts each process made.
type Ended struct {
	Kind     string   `json:"kind"`
	Pushed   uint64   `json:"pushed"`
	Blocked  uint64   `json:"blocked"`
	Exited   uint64   `json:"exited"`
	Running  uint64   `json:"running"`
	Expected *float64 `json:"expected"`
}

// A reason attempts of one kind blocked, and how many. `inferred` of them
// have no word in their trace (from before reasons were words): the kernel
// derived the reason from the searches' words, or the trace's sentence names
// it. A block nothing names counts under "unrecorded".
type Reason struct {
	Kind     string `json:"kind"`
	Reason   string `json:"reason"`
	Count    uint64 `json:"count"`
	Inferred uint64 `json:"inferred"`
}

// Where a goal came from: the goal, the commit and its subject.
type About struct {
	Goal    string `json:"goal"`
	From    string `json:"from"`
	Subject string `json:"subject"`
}

// What a push cost, and the commit it pushed. Cost is generation plus time,
// each summed over every bon process run to reach the push.
type Push struct {
	Commit         *string  `json:"commit"`
	Cost           *float64 `json:"cost"`
	Generation     *float64 `json:"generation"`
	TimeCost       *float64 `json:"time_cost"`
	ToSelection    *float64 `json:"to_selection"`
	Counterexample *float64 `json:"counterexample"`
	// The wall time of every search run to reach it, summed as cost is.
	Seconds   *float64 `json:"seconds"`
	Searches  *uint64  `json:"searches"`
	Processes *uint64  `json:"processes"`
}

// The bon processes of one goal: one row of the traces.
type GoalTrace struct {
	Kind       string  `json:"kind"`
	Title      string  `json:"title"`
	About      About   `json:"about"`
	Outcome    string  `json:"outcome"`
	Sentence   string  `json:"sentence"`
	Cost       float64 `json:"cost"`
	Generation float64 `json:"generation"`
	TimeCost   float64 `json:"time_cost"`
	// Its searches' wall time, summed.
	Seconds   float64      `json:"seconds"`
	Push      *Push        `json:"push"`
	Time      int64        `json:"time"`
	Running   bool         `json:"running"`
	Processes []BonProcess `json:"processes"`
}

// One run of a bon command, by its pid.
type BonProcess struct {
	Pid uint64 `json:"pid"`
	// Its trace directory under .bon/traces: `<pid>`, or `<pid>.<start>` when
	// an earlier bon process had the same pid.
	Trace      string  `json:"trace"`
	Running    bool    `json:"running"`
	Kind       string  `json:"kind"`
	Goal       string  `json:"goal"`
	Title      string  `json:"title"`
	About      About   `json:"about"`
	Outcome    string  `json:"outcome"`
	Sentence   string  `json:"sentence"`
	Cost       float64 `json:"cost"`
	Generation float64 `json:"generation"`
	TimeCost   float64 `json:"time_cost"`
	// Its searches' wall time, summed.
	Seconds float64  `json:"seconds"`
	Push    *Push    `json:"push"`
	Limit   *float64 `json:"limit"`
	Time    int64    `json:"time"`
	// Each line of its transitions file.
	Transitions []string      `json:"transitions"`
	Searches    []SearchTrace `json:"searches"`
	// Seconds its checks of trunk took before its first search, from their logs.
	CheckSeconds *float64 `json:"check_seconds"`
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
	// How many verified candidates the trace's summary recorded.
	RecordedVerified *uint64 `json:"recorded_verified"`
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
	// A running search's agent processes that have not returned: waiting
	// (on an agent_processes slot, or making its working directory), in
	// flight (its program runs), in checks (its program returned; it is judged).
	Waiting  uint64 `json:"waiting"`
	InFlight uint64 `json:"in_flight"`
	InChecks uint64 `json:"in_checks"`
	// The host's semaphore sizes it ran under, where its trace records them.
	Pools Pools `json:"pools"`
	// How many distinct trees its candidates wrote; none where git lacks one.
	Trees *uint64 `json:"trees"`
	// Agent processes per behavior: for each distinct `out` its verified
	// candidates show, how many show it, in the order each first appears.
	Behaviors  []uint64 `json:"behaviors"`
	Candidates []Facts  `json:"candidates"`
	// A code or compaction search: how its attempt ended (pushed, blocked,
	// landed, exited, running).
	End *string `json:"end"`
	// A blocked attempt's reason, by its word; none where nothing names it.
	Reason *string `json:"reason"`
	// Where the reason came from: recorded (the trace's word), kernel (derived
	// from the searches' words) or sentence (the trace's sentence).
	ReasonFrom *string `json:"reason_from"`
}

// The sizes of the host's two semaphores.
type Pools struct {
	AgentProcesses *uint64 `json:"agent_processes"`
	CheckProcesses *uint64 `json:"check_processes"`
}

// What a search was granted with.
type Params struct {
	Goal      GoalRef  `json:"goal"`
	Base      string   `json:"base"`
	N         *uint64  `json:"n"`
	Limit     *float64 `json:"limit"`
	Authority string   `json:"authority"`
}

// A search's goal: a trunk commit, a candidate of a search, or a transcript.
type GoalRef struct {
	Trunk      *string `json:"trunk"`
	Candidate  *string `json:"candidate"`
	Transcript *string `json:"transcript"`
}

// One agent process, from its facts.json.
type Facts struct {
	Index uint64 `json:"index"`
	// The program it ran (older traces: their `harness`).
	Program    *string  `json:"program"`
	Model      *string  `json:"model"`
	Generation *float64 `json:"generation"`
	Commit     *string  `json:"commit"`
	Accepted   bool     `json:"accepted"`
	// Verus verified it.
	Proved       bool    `json:"proved"`
	Verified     bool    `json:"verified"`
	Rank         *int64  `json:"rank"`
	Diff         *uint64 `json:"diff"`
	LinesAdded   *uint64 `json:"lines_added"`
	LinesRemoved *uint64 `json:"lines_removed"`
	// Its commit's tree, where git has it.
	Tree *string `json:"tree"`
	// killed, over limit, price mismatch.
	Flags []string `json:"flags"`
	Logs  []string `json:"logs"`
	// Seconds its program ran, from its log.
	ProgramSeconds *float64 `json:"program_seconds"`
	// Seconds of its checks, summed from their logs.
	CheckSeconds *float64 `json:"check_seconds"`
	Changed      []string `json:"changed"`
	// A hash of each agree check's output: candidates with the same agree.
	Out []uint64 `json:"out"`
	// A test's verdict on each member it ran on, by index; trunk's head (or a
	// compaction's goal) is -1. Empty for a candidate that is no test.
	Accepts []Tuple2[int64, bool] `json:"accepts"`
	// A test's verdict on each foil it ran on, by index in the foil search.
	AcceptsFoils []Tuple2[int64, bool] `json:"accepts_foils"`
	// It, in the one shape every record has.
	Record Record `json:"record"`
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

// An intent taken off the queue: by the commit on trunk's history whose diff
// removed its line, with that commit's subject and time.
type Retired struct {
	Id      uint64 `json:"id"`
	Intent  string `json:"intent"`
	Commit  string `json:"commit"`
	Subject string `json:"subject"`
	Time    *int64 `json:"time"`
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

// A network service a program calls.
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
