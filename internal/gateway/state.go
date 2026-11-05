// Package gateway runs the egress proxy as a long-lived process: it loads the effective policy,
// hot-reloads it, serves the proxy and a loopback-only admin endpoint, and shuts down cleanly.
package gateway

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/middle-systems/kennel/internal/policy"
)

// maxPolicyFile bounds how much of the policy file is read per poll.
const maxPolicyFile = policy.MaxPolicyBytes + 1

// State holds the active compiled policy and the outcome of the latest reload attempt.
type State struct {
	path   string
	logger *slog.Logger
	cur    atomic.Pointer[policy.Compiled]

	mu         sync.Mutex
	lastSum    [32]byte
	haveSum    bool
	lastErr    string
	lastErrSum [32]byte
	reloadedAt time.Time
	reloads    int
	failures   int
}

// NewState loads the policy at path. It fails if the file is missing or invalid: the gateway must
// not start without a policy it understands (and never falls back to allowing anything).
func NewState(path string, logger *slog.Logger) (*State, error) {
	s := &State{path: path, logger: logger}
	raw, err := readPolicyFile(path)
	if err != nil {
		return nil, err
	}
	c, err := compile(path, raw)
	if err != nil {
		return nil, err
	}
	s.cur.Store(c)
	s.lastSum, s.haveSum = sha256.Sum256(raw), true
	s.reloadedAt = time.Now()
	return s, nil
}

// Current returns the active policy. It is never nil after NewState succeeds.
func (s *State) Current() *policy.Compiled { return s.cur.Load() }

// Reload is the outcome of one Poll.
type Reload struct {
	Changed bool
	Failed  bool
	Err     error
	Old     *policy.Compiled
	New     *policy.Compiled
}

// Poll re-reads the policy file and, if its content changed, compiles and swaps it in. An invalid
// or unreadable file leaves the previous policy active: a typo must neither open the gate nor
// shut it. The same bad content is reported once, not on every poll.
func (s *State) Poll() Reload {
	raw, err := readPolicyFile(s.path)
	if err != nil {
		return s.fail(err, sha256.Sum256([]byte(err.Error())))
	}
	sum := sha256.Sum256(raw)

	s.mu.Lock()
	unchanged := s.haveSum && sum == s.lastSum
	repeatBad := s.lastErr != "" && sum == s.lastErrSum
	s.mu.Unlock()
	if unchanged || repeatBad {
		return Reload{}
	}

	c, err := compile(s.path, raw)
	if err != nil {
		return s.fail(err, sum)
	}
	old := s.cur.Swap(c)
	s.mu.Lock()
	s.lastSum, s.haveSum = sum, true
	s.lastErr = ""
	s.reloadedAt = time.Now()
	s.reloads++
	s.mu.Unlock()
	return Reload{Changed: true, Old: old, New: c}
}

func (s *State) fail(err error, sum [32]byte) Reload {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr != "" && sum == s.lastErrSum {
		return Reload{} // already reported
	}
	s.lastErr, s.lastErrSum = err.Error(), sum
	s.failures++
	return Reload{Failed: true, Err: err, Old: s.cur.Load()}
}

// Status is a snapshot for the admin endpoint.
type Status struct {
	PolicyHash  string    `json:"policy_hash"`
	Rules       int       `json:"rules"`
	Relaxations []string  `json:"relaxations"`
	LoadedAt    time.Time `json:"loaded_at"`
	Reloads     int       `json:"reloads"`
	Failures    int       `json:"reload_failures"`
	LastError   string    `json:"last_reload_error,omitempty"`
}

// Status reports the active policy and reload history.
func (s *State) Status() Status {
	c := s.cur.Load()
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		PolicyHash:  c.Hash,
		Rules:       len(c.Policy.Rules),
		Relaxations: policy.Relaxations(c.Findings),
		LoadedAt:    s.reloadedAt,
		Reloads:     s.reloads,
		Failures:    s.failures,
		LastError:   s.lastErr,
	}
}

func readPolicyFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path is the operator-supplied --policy flag, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxPolicyFile))
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	if len(raw) == 0 {
		// An empty file is what a truncating writer exposes mid-write; never treat it as a policy.
		return nil, errors.New("read policy: file is empty")
	}
	return raw, nil
}

func compile(path string, raw []byte) (*policy.Compiled, error) {
	p, err := policy.Parse(path, raw)
	if err != nil {
		return nil, err
	}
	// The gateway only ever loads the effective policy written by the host CLI, where rules carry
	// their Source.
	return policy.Compile(p, true)
}
